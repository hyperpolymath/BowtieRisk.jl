# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskVPUExt -- VPU (Vector Processing Unit) acceleration for BowtieRisk.jl
# SIMD-vectorized probability calculations exploiting wide vector registers
# for parallel-within-sample barrier evaluation.

module BowtieRiskVPUExt

using BowtieRisk
using AcceleratorGate
using AcceleratorGate: VPUBackend, JuliaBackend, _record_diagnostic!,
    register_operation!, track_allocation!, track_deallocation!

function __init__()
    register_operation!(VPUBackend, :monte_carlo_step)
    register_operation!(VPUBackend, :barrier_eval)
    register_operation!(VPUBackend, :probability_sample)
end

# ============================================================================
# VPU SIMD-Vectorized Probability Calculations
# ============================================================================
#
# VPU architecture excels at data-parallel SIMD operations across wide
# vector registers (256-bit to 2048-bit). For risk computation:
# - Process 4/8/16 samples simultaneously per vector lane
# - Vectorize barrier effectiveness computation across samples
# - Use SIMD gather/scatter for path-barrier mapping

const VPU_LANE_WIDTH = 8  # Simulate 512-bit vector registers (8 x Float64)

"""
    _simd_barrier_reduction(eff::Vector{Float64}, deg::Vector{Float64},
                            rand_vals::Matrix{Float64}) -> Vector{Float64}

Vectorized barrier reduction: processes VPU_LANE_WIDTH samples simultaneously.
rand_vals is (n_barriers x n_samples) for coalesced SIMD access.
Returns per-sample reduction factors.
"""
function _simd_barrier_reduction(eff::Vector{Float64}, deg::Vector{Float64},
                                  rand_vals::Matrix{Float64}, n_samples::Int)
    n_barriers = length(eff)
    results = ones(Float64, n_samples)

    # Process in SIMD-width chunks
    for chunk_start in 1:VPU_LANE_WIDTH:n_samples
        chunk_end = min(chunk_start + VPU_LANE_WIDTH - 1, n_samples)
        chunk_size = chunk_end - chunk_start + 1

        # SIMD lane: accumulate reduction for each sample in the chunk
        @inbounds for b in 1:n_barriers
            e = eff[b]
            d = deg[b]
            @simd for lane in 1:chunk_size
                s = chunk_start + lane - 1
                actual_deg = min(d * 2.0 * rand_vals[b, s], 1.0)
                effective = clamp(e * (1.0 - actual_deg), 0.0, 1.0)
                results[s] *= (1.0 - effective)
            end
        end
    end

    return results
end

"""
    BowtieRisk.backend_coprocessor_monte_carlo_step(::VPUBackend, model, barrier_dists, n_samples)

VPU SIMD-vectorized Monte Carlo: processes VPU_LANE_WIDTH samples per
vector instruction, achieving near-peak throughput on vector hardware.
"""
function BowtieRisk.backend_coprocessor_monte_carlo_step(b::VPUBackend,
                                                          model::BowtieRisk.BowtieModel,
                                                          barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                                          n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < VPU_LANE_WIDTH && return nothing

    # Align sample count to SIMD width for optimal lane utilisation
    aligned_samples = ((n_samples + VPU_LANE_WIDTH - 1) >> 3) << 3

    track_allocation!(b, Int64(aligned_samples * 100 * 8))

    try
        results = zeros(Float64, aligned_samples)

        for path in model.threat_paths
            base = clamp(path.threat.probability, 0.0, 1.0)
            n_barriers = length(path.barriers)
            n_barriers == 0 && continue

            eff = Float64[item.effectiveness for item in path.barriers]
            deg = Float64[item.degradation for item in path.barriers]

            # Pre-generate random values in barrier-major order for coalesced SIMD
            rand_vals = rand(Float64, n_barriers, aligned_samples)

            reduction = _simd_barrier_reduction(eff, deg, rand_vals, aligned_samples)

            # SIMD vectorized combination with existing results
            @simd for s in 1:aligned_samples
                residual = base * reduction[s]
                if results[s] == 0.0
                    results[s] = residual
                else
                    results[s] = 1.0 - (1.0 - results[s]) * (1.0 - residual)
                end
            end
        end

        track_deallocation!(b, Int64(aligned_samples * 100 * 8))
        return results[1:n_samples]
    catch ex
        track_deallocation!(b, Int64(aligned_samples * 100 * 8))
        _record_diagnostic!(b, "runtime_errors")
        @warn "VPU Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_barrier_eval(::VPUBackend, barriers, factors, model)

VPU SIMD-vectorized barrier evaluation.
"""
function BowtieRisk.backend_coprocessor_barrier_eval(b::VPUBackend,
                                                      barriers::Vector{BowtieRisk.Barrier},
                                                      factors::Vector{BowtieRisk.EscalationFactor},
                                                      prob_model::BowtieRisk.ProbabilityModel)
    length(barriers) < VPU_LANE_WIDTH && return nothing

    try
        factor_reduction = prod(1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors; init=1.0)

        eff = Float64[item.effectiveness for item in barriers]
        deg = Float64[item.degradation for item in barriers]
        n = length(barriers)

        result = 1.0
        @inbounds @simd for i in 1:n
            effective = clamp(eff[i] * (1.0 - deg[i]) * factor_reduction, 0.0, 1.0)
            result *= (1.0 - effective)
        end

        return result
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_probability_sample(::VPUBackend, dist, n_samples)

VPU SIMD-vectorized distribution sampling.
"""
function BowtieRisk.backend_coprocessor_probability_sample(b::VPUBackend,
                                                            dist::BowtieRisk.BarrierDistribution,
                                                            n_samples::Int)
    n_samples < VPU_LANE_WIDTH && return nothing
    aligned = ((n_samples + VPU_LANE_WIDTH - 1) >> 3) << 3

    if dist.kind == :fixed
        return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)
    elseif dist.kind == :triangular
        try
            low, mode, high = dist.params
            (low <= mode <= high && low < high) || return nothing
            c = (mode - low) / (high - low)
            u = rand(Float64, aligned)
            samples = Vector{Float64}(undef, aligned)

            @inbounds @simd for i in 1:aligned
                if u[i] < c
                    samples[i] = low + sqrt(u[i] * (high - low) * (mode - low))
                else
                    samples[i] = high - sqrt((1.0 - u[i]) * (high - low) * (high - mode))
                end
            end
            return samples[1:n_samples]
        catch ex
            _record_diagnostic!(b, "runtime_errors")
            return nothing
        end
    end
    return nothing
end

function BowtieRisk.backend_coprocessor_risk_aggregate(b::VPUBackend, args...)
    return nothing
end

function BowtieRisk.backend_coprocessor_correlation_matrix(b::VPUBackend, args...)
    return nothing
end

end # module BowtieRiskVPUExt
