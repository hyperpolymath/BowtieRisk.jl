# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskFPGAExt -- FPGA streaming pipeline acceleration for BowtieRisk.jl
# Exploits FPGA's streaming architecture for continuous Monte Carlo simulation
# and real-time risk monitoring pipelines.

module BowtieRiskFPGAExt

using BowtieRisk
using AcceleratorGate
using AcceleratorGate: FPGABackend, JuliaBackend, _record_diagnostic!,
    register_operation!, track_allocation!, track_deallocation!

function __init__()
    register_operation!(FPGABackend, :monte_carlo_step)
    register_operation!(FPGABackend, :barrier_eval)
    register_operation!(FPGABackend, :probability_sample)
end

# ============================================================================
# FPGA Streaming Monte Carlo Pipeline
# ============================================================================
#
# FPGA architecture maps naturally to streaming Monte Carlo:
# - Pipeline stage 1: LFSR-based pseudo-random number generation
# - Pipeline stage 2: Barrier effectiveness sampling (fixed-point)
# - Pipeline stage 3: Path residual accumulation
# - Pipeline stage 4: Top-event probability combination
#
# The pipeline processes one sample per clock cycle at steady state,
# achieving throughput unmatched by GPU or CPU for streaming workloads.

"""
    _lfsr_stream(n::Int, seed::UInt32) -> Vector{Float64}

Simulate FPGA LFSR-based random number stream.
Uses a 32-bit maximal-length LFSR with taps at [32, 22, 2, 1].
"""
function _lfsr_stream(n::Int, seed::UInt32)
    results = Vector{Float64}(undef, n)
    state = seed == 0 ? UInt32(0xACE1) : seed  # LFSR must not be zero

    for i in 1:n
        # Galois LFSR with polynomial x^32 + x^22 + x^2 + x + 1
        bit = xor(state >> 31, state >> 21, state >> 1, state) & UInt32(1)
        state = (state << 1) | bit
        results[i] = Float64(state) / Float64(typemax(UInt32))
    end
    return results
end

"""
    _fixed_point_barrier_pipeline(barriers, rand_stream) -> Float64

Simulate FPGA fixed-point barrier evaluation pipeline.
Uses 16.16 fixed-point arithmetic matching typical FPGA DSP slice precision.
"""
function _fixed_point_barrier_pipeline(barriers::Vector{BowtieRisk.Barrier},
                                        rand_stream::Vector{Float64})
    # 16.16 fixed-point: multiply by 2^16, round, operate, divide back
    FP_SCALE = 65536.0
    reduction = FP_SCALE  # 1.0 in fixed point

    for (i, b) in enumerate(barriers)
        eff_fp = round(Int64, b.effectiveness * FP_SCALE)
        deg_fp = round(Int64, b.degradation * FP_SCALE)

        # Random degradation from LFSR stream
        rand_idx = mod1(i, length(rand_stream))
        rand_fp = round(Int64, rand_stream[rand_idx] * FP_SCALE)

        # actual_degradation = degradation * 2 * random (clamped to 1.0)
        actual_deg = min((deg_fp * 2 * rand_fp) >> 16, Int64(FP_SCALE))

        # effective = eff * (1 - actual_deg)
        effective = (eff_fp * (Int64(FP_SCALE) - actual_deg)) >> 16
        effective = clamp(effective, Int64(0), Int64(FP_SCALE))

        # reduction *= (1 - effective)
        reduction = (reduction * (Int64(FP_SCALE) - effective)) >> 16
    end

    return Float64(reduction) / FP_SCALE
end

"""
    BowtieRisk.backend_coprocessor_monte_carlo_step(::FPGABackend, model, barrier_dists, n_samples)

FPGA streaming pipeline Monte Carlo simulation.
Processes samples through a fixed-point pipeline with LFSR random generation,
simulating the FPGA's streaming architecture.
"""
function BowtieRisk.backend_coprocessor_monte_carlo_step(b::FPGABackend,
                                                          model::BowtieRisk.BowtieModel,
                                                          barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                                          n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 64 && return nothing

    total_barriers = sum(length(p.barriers) for p in model.threat_paths; init=0)
    total_barriers == 0 && return nothing

    track_allocation!(b, Int64(n_samples * total_barriers * 8))

    try
        results = Vector{Float64}(undef, n_samples)
        seed = UInt32(rand(UInt32))

        for sample in 1:n_samples
            # Generate LFSR stream for this sample (one seed per sample)
            sample_seed = seed + UInt32(sample)
            rand_stream = _lfsr_stream(total_barriers, sample_seed)

            top_prod = 1.0
            for path in model.threat_paths
                base = clamp(path.threat.probability, 0.0, 1.0)
                reduction = _fixed_point_barrier_pipeline(path.barriers, rand_stream)
                residual = base * reduction
                top_prod *= (1.0 - residual)
            end
            results[sample] = 1.0 - top_prod
        end

        track_deallocation!(b, Int64(n_samples * total_barriers * 8))
        return results
    catch ex
        track_deallocation!(b, Int64(n_samples * total_barriers * 8))
        _record_diagnostic!(b, "runtime_errors")
        @warn "FPGA Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_barrier_eval(::FPGABackend, barriers, factors, model)

FPGA fixed-point barrier evaluation pipeline.
Uses deterministic fixed-point arithmetic for reproducible results.
"""
function BowtieRisk.backend_coprocessor_barrier_eval(b::FPGABackend,
                                                      barriers::Vector{BowtieRisk.Barrier},
                                                      factors::Vector{BowtieRisk.EscalationFactor},
                                                      prob_model::BowtieRisk.ProbabilityModel)
    isempty(barriers) && return nothing

    try
        FP_SCALE = 65536.0
        factor_reduction_fp = round(Int64,
            prod(1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors; init=1.0) * FP_SCALE)

        reduction = Int64(round(FP_SCALE))  # 1.0 in fixed point
        for b_item in barriers
            eff_fp = round(Int64, b_item.effectiveness * FP_SCALE)
            deg_fp = round(Int64, b_item.degradation * FP_SCALE)

            effective = (eff_fp * (Int64(round(FP_SCALE)) - deg_fp)) >> 16
            effective = (effective * factor_reduction_fp) >> 16
            effective = clamp(effective, Int64(0), Int64(round(FP_SCALE)))

            reduction = (reduction * (Int64(round(FP_SCALE)) - effective)) >> 16
        end

        return Float64(reduction) / FP_SCALE
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_probability_sample(::FPGABackend, dist, n_samples)

FPGA LFSR-based probability sampling for fixed and simple distributions.
"""
function BowtieRisk.backend_coprocessor_probability_sample(b::FPGABackend,
                                                            dist::BowtieRisk.BarrierDistribution,
                                                            n_samples::Int)
    n_samples < 32 && return nothing
    dist.kind == :fixed && return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)

    if dist.kind == :triangular
        try
            low, mode, high = dist.params
            (low <= mode <= high && low < high) || return nothing

            stream = _lfsr_stream(n_samples, UInt32(rand(UInt32)))
            c = (mode - low) / (high - low)
            samples = Vector{Float64}(undef, n_samples)
            for i in 1:n_samples
                u = stream[i]
                if u < c
                    samples[i] = low + sqrt(u * (high - low) * (mode - low))
                else
                    samples[i] = high - sqrt((1.0 - u) * (high - low) * (high - mode))
                end
            end
            return samples
        catch ex
            _record_diagnostic!(b, "runtime_errors")
            return nothing
        end
    end

    return nothing
end

function BowtieRisk.backend_coprocessor_risk_aggregate(b::FPGABackend, args...)
    return nothing  # Simple aggregation faster on CPU
end

function BowtieRisk.backend_coprocessor_correlation_matrix(b::FPGABackend, args...)
    return nothing  # Matrix operations not suited to FPGA streaming
end

end # module BowtieRiskFPGAExt
