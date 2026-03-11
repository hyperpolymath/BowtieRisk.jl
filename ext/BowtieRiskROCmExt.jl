# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskROCmExt -- AMD ROCm GPU acceleration for BowtieRisk.jl
# Parallel Monte Carlo simulation and batch barrier evaluation on AMD GPUs.

module BowtieRiskROCmExt

using BowtieRisk
using AMDGPU
using AMDGPU: ROCArray, ROCVector, ROCMatrix
using KernelAbstractions
using KernelAbstractions: @kernel, @index, @Const
using AcceleratorGate: ROCmBackend, JuliaBackend, _record_diagnostic!

# ============================================================================
# ROCm Kernel: Parallel Monte Carlo Barrier Sampling
# ============================================================================

@kernel function mc_barrier_rocm_kernel!(results, @Const(base_probs),
                                          @Const(effectiveness), @Const(degradation),
                                          @Const(barrier_offsets), @Const(n_barriers_per_path),
                                          n_paths::Int32, seed::UInt64)
    sample_idx = @index(Global)

    state = seed + UInt64(sample_idx) * UInt64(6364136223846793005)

    top_prod = 1.0
    for p in Int32(1):n_paths
        base = base_probs[p]
        barrier_reduction = 1.0

        offset = barrier_offsets[p]
        nb = n_barriers_per_path[p]

        for b in Int32(1):nb
            idx = offset + b
            eff = effectiveness[idx]
            deg = degradation[idx]

            state = xor(state, state << 13)
            state = xor(state, state >> 7)
            state = xor(state, state << 17)
            rand_val = Float64(state & UInt64(0x000FFFFFFFFFFFFF)) / Float64(UInt64(0x000FFFFFFFFFFFFF))

            actual_deg = deg * 2.0 * rand_val
            actual_deg = min(actual_deg, 1.0)
            effective = eff * (1.0 - actual_deg)
            effective = clamp(effective, 0.0, 1.0)
            barrier_reduction *= (1.0 - effective)
        end

        residual = base * barrier_reduction
        top_prod *= (1.0 - residual)
    end

    results[sample_idx] = 1.0 - top_prod
end

"""
    BowtieRisk.backend_monte_carlo_step(::ROCmBackend, model, barrier_dists, n_samples)

ROCm GPU-accelerated Monte Carlo step on AMD GPUs.
"""
function BowtieRisk.backend_monte_carlo_step(b::ROCmBackend,
                                              model::BowtieRisk.BowtieModel,
                                              barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                              n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 256 && return nothing

    base_probs = Float64[p.threat.probability for p in model.threat_paths]
    all_eff = Float64[]
    all_deg = Float64[]
    barrier_offsets = Int32[]
    barriers_per_path = Int32[]

    offset = Int32(0)
    for path in model.threat_paths
        push!(barrier_offsets, offset)
        push!(barriers_per_path, Int32(length(path.barriers)))
        for barrier in path.barriers
            push!(all_eff, barrier.effectiveness)
            push!(all_deg, barrier.degradation)
        end
        offset += Int32(length(path.barriers))
    end

    isempty(all_eff) && return nothing

    try
        d_results = AMDGPU.zeros(Float64, n_samples)
        d_base = ROCArray(base_probs)
        d_eff = ROCArray(all_eff)
        d_deg = ROCArray(all_deg)
        d_offsets = ROCArray(barrier_offsets)
        d_nbp = ROCArray(barriers_per_path)

        seed = UInt64(rand(UInt64))
        kernel = mc_barrier_rocm_kernel!(KernelAbstractions.ROCDevice(), 256)
        kernel(d_results, d_base, d_eff, d_deg, d_offsets, d_nbp,
               Int32(n_paths), seed; ndrange=n_samples)
        KernelAbstractions.synchronize(KernelAbstractions.ROCDevice())

        return Array(d_results)
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        @warn "ROCm Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

function BowtieRisk.backend_risk_aggregate(b::ROCmBackend, samples::Vector{Float64})
    length(samples) < 1024 && return nothing
    try
        d = ROCArray(samples)
        return Float64(sum(d) / length(d))
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_barrier_eval(b::ROCmBackend,
                                          barriers::Vector{BowtieRisk.Barrier},
                                          factors::Vector{BowtieRisk.EscalationFactor},
                                          prob_model::BowtieRisk.ProbabilityModel)
    length(barriers) < 32 && return nothing
    try
        eff = Float64[item.effectiveness for item in barriers]
        deg = Float64[item.degradation for item in barriers]
        d_eff = ROCArray(eff)
        d_deg = ROCArray(deg)
        factor_reduction = prod(1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors; init=1.0)
        d_effective = clamp.(d_eff .* (1.0 .- d_deg) .* factor_reduction, 0.0, 1.0)
        return Float64(prod(1.0 .- Array(d_effective)))
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_correlation_matrix(b::ROCmBackend, samples::Matrix{Float64})
    size(samples, 1) < 64 && return nothing
    try
        d = ROCArray(samples)
        means = sum(d, dims=1) ./ size(d, 1)
        centered = d .- means
        cov_mat = Array(centered' * centered) ./ (size(d, 1) - 1)
        stds = sqrt.(max.(diag(cov_mat), 1e-12))
        return cov_mat ./ (stds * stds')
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_probability_sample(b::ROCmBackend,
                                                dist::BowtieRisk.BarrierDistribution,
                                                n_samples::Int)
    n_samples < 1024 && return nothing
    dist.kind == :fixed && return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)
    return nothing
end

end # module BowtieRiskROCmExt
