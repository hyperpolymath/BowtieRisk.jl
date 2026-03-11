# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskMetalExt -- Apple Metal GPU acceleration for BowtieRisk.jl
# Parallel Monte Carlo simulation and batch barrier evaluation on Apple Silicon.

module BowtieRiskMetalExt

using BowtieRisk
using Metal
using Metal: MtlArray, MtlVector, MtlMatrix
using KernelAbstractions
using KernelAbstractions: @kernel, @index, @Const
using AcceleratorGate: MetalBackend, JuliaBackend, _record_diagnostic!

# ============================================================================
# Metal Kernel: Parallel Monte Carlo Barrier Sampling
# ============================================================================

@kernel function mc_barrier_metal_kernel!(results, @Const(base_probs),
                                           @Const(effectiveness), @Const(degradation),
                                           @Const(barrier_offsets), @Const(n_barriers_per_path),
                                           n_paths::Int32, seed::UInt32)
    sample_idx = @index(Global)

    # Philox-style PRNG for Metal (32-bit friendly)
    state = seed + UInt32(sample_idx) * UInt32(2654435761)

    top_prod = Float32(1.0)
    for p in Int32(1):n_paths
        base = Float32(base_probs[p])
        barrier_reduction = Float32(1.0)

        offset = barrier_offsets[p]
        nb = n_barriers_per_path[p]

        for b in Int32(1):nb
            idx = offset + b
            eff = Float32(effectiveness[idx])
            deg = Float32(degradation[idx])

            state = xor(state, state << 13)
            state = xor(state, state >> 17)
            state = xor(state, state << 5)
            rand_val = Float32(state & UInt32(0x00FFFFFF)) / Float32(UInt32(0x00FFFFFF))

            actual_deg = deg * Float32(2.0) * rand_val
            actual_deg = min(actual_deg, Float32(1.0))
            effective = eff * (Float32(1.0) - actual_deg)
            effective = clamp(effective, Float32(0.0), Float32(1.0))
            barrier_reduction *= (Float32(1.0) - effective)
        end

        residual = base * barrier_reduction
        top_prod *= (Float32(1.0) - residual)
    end

    results[sample_idx] = Float32(1.0) - top_prod
end

"""
    BowtieRisk.backend_monte_carlo_step(::MetalBackend, model, barrier_dists, n_samples)

Metal GPU-accelerated Monte Carlo step on Apple Silicon.
Uses Float32 for Metal's native precision, converting back to Float64.
"""
function BowtieRisk.backend_monte_carlo_step(b::MetalBackend,
                                              model::BowtieRisk.BowtieModel,
                                              barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                              n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 256 && return nothing

    base_probs = Float32[p.threat.probability for p in model.threat_paths]
    all_eff = Float32[]
    all_deg = Float32[]
    barrier_offsets = Int32[]
    barriers_per_path = Int32[]

    offset = Int32(0)
    for path in model.threat_paths
        push!(barrier_offsets, offset)
        push!(barriers_per_path, Int32(length(path.barriers)))
        for barrier in path.barriers
            push!(all_eff, Float32(barrier.effectiveness))
            push!(all_deg, Float32(barrier.degradation))
        end
        offset += Int32(length(path.barriers))
    end

    isempty(all_eff) && return nothing

    try
        d_results = Metal.zeros(Float32, n_samples)
        d_base = MtlArray(base_probs)
        d_eff = MtlArray(all_eff)
        d_deg = MtlArray(all_deg)
        d_offsets = MtlArray(barrier_offsets)
        d_nbp = MtlArray(barriers_per_path)

        seed = UInt32(rand(UInt32))
        kernel = mc_barrier_metal_kernel!(KernelAbstractions.MetalDevice(), 256)
        kernel(d_results, d_base, d_eff, d_deg, d_offsets, d_nbp,
               Int32(n_paths), seed; ndrange=n_samples)
        KernelAbstractions.synchronize(KernelAbstractions.MetalDevice())

        return Float64.(Array(d_results))
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        @warn "Metal Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

function BowtieRisk.backend_risk_aggregate(b::MetalBackend, samples::Vector{Float64})
    length(samples) < 1024 && return nothing
    try
        d = MtlArray(Float32.(samples))
        result = Float64(sum(d) / length(d))
        return result
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_barrier_eval(b::MetalBackend,
                                          barriers::Vector{BowtieRisk.Barrier},
                                          factors::Vector{BowtieRisk.EscalationFactor},
                                          prob_model::BowtieRisk.ProbabilityModel)
    length(barriers) < 32 && return nothing
    try
        eff = Float32[item.effectiveness for item in barriers]
        deg = Float32[item.degradation for item in barriers]
        d_eff = MtlArray(eff)
        d_deg = MtlArray(deg)
        factor_reduction = Float32(prod(1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors; init=1.0))
        d_effective = clamp.(d_eff .* (Float32(1) .- d_deg) .* factor_reduction, Float32(0), Float32(1))
        result = Float64(prod(Float32(1) .- Array(d_effective)))
        return result
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_correlation_matrix(b::MetalBackend, samples::Matrix{Float64})
    size(samples, 1) < 64 && return nothing
    try
        d = MtlArray(Float32.(samples))
        means = sum(d, dims=1) ./ size(d, 1)
        centered = d .- means
        cov_mat = Array(centered' * centered) ./ (size(d, 1) - 1)
        stds = sqrt.(max.(diag(cov_mat), 1e-12f0))
        return Float64.(cov_mat ./ (stds * stds'))
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_probability_sample(b::MetalBackend,
                                                dist::BowtieRisk.BarrierDistribution,
                                                n_samples::Int)
    n_samples < 1024 && return nothing
    dist.kind == :fixed && return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)
    return nothing  # Complex distributions fall back to CPU
end

end # module BowtieRiskMetalExt
