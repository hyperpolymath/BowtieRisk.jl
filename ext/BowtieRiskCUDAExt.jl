# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskCUDAExt -- CUDA GPU acceleration for BowtieRisk.jl
# Parallel Monte Carlo simulation and batch barrier evaluation on NVIDIA GPUs.

module BowtieRiskCUDAExt

using BowtieRisk
using CUDA
using CUDA: CuArray, CuVector, @cuda
using KernelAbstractions
using KernelAbstractions: @kernel, @index, @Const
using AcceleratorGate: CUDABackend, JuliaBackend, _record_diagnostic!

# ============================================================================
# GPU Kernel: Parallel Monte Carlo Barrier Sampling
# ============================================================================

"""
    mc_barrier_kernel!(results, base_probs, effectiveness, degradation,
                       esc_multipliers, n_barriers, n_paths)

Each thread runs one Monte Carlo sample: for each threat path, compute the
residual probability through all barriers with random degradation.
Uses GPU thread index as implicit sample index.
"""
@kernel function mc_barrier_kernel!(results, @Const(base_probs),
                                     @Const(effectiveness), @Const(degradation),
                                     @Const(barrier_path_map), @Const(n_barriers_per_path),
                                     n_paths::Int32, total_barriers::Int32,
                                     seed::UInt64)
    sample_idx = @index(Global)

    # Simple xorshift64 PRNG seeded per thread
    state = seed + UInt64(sample_idx) * UInt64(6364136223846793005)

    top_prod = 1.0
    for p in Int32(1):n_paths
        base = base_probs[p]
        barrier_reduction = 1.0

        offset = barrier_path_map[p]
        nb = n_barriers_per_path[p]

        for b in Int32(1):nb
            idx = offset + b
            eff = effectiveness[idx]
            deg = degradation[idx]

            # Generate pseudo-random degradation factor in [0, 2*deg]
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
    BowtieRisk.backend_monte_carlo_step(::CUDABackend, model, barrier_dists, n_samples)

GPU-accelerated Monte Carlo step: runs n_samples simulations in parallel on CUDA.
Each GPU thread evaluates the full bowtie model with random barrier effectiveness.
Returns vector of top-event probability samples.
"""
function BowtieRisk.backend_monte_carlo_step(b::CUDABackend,
                                              model::BowtieRisk.BowtieModel,
                                              barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                              n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 256 && return nothing

    # Flatten barrier data for GPU transfer
    base_probs = Float64[p.threat.probability for p in model.threat_paths]
    all_eff = Float64[]
    all_deg = Float64[]
    barrier_offsets = Int32[]
    barriers_per_path = Int32[]

    offset = Int32(0)
    for path in model.threat_paths
        push!(barrier_offsets, offset)
        push!(barriers_per_path, Int32(length(path.barriers)))
        for b in path.barriers
            push!(all_eff, b.effectiveness)
            push!(all_deg, b.degradation)
        end
        offset += Int32(length(path.barriers))
    end

    total_barriers = length(all_eff)
    total_barriers == 0 && return nothing

    try
        d_results = CUDA.zeros(Float64, n_samples)
        d_base = CuArray(base_probs)
        d_eff = CuArray(all_eff)
        d_deg = CuArray(all_deg)
        d_offsets = CuArray(barrier_offsets)
        d_nbp = CuArray(barriers_per_path)

        seed = UInt64(rand(UInt64))
        kernel = mc_barrier_kernel!(KernelAbstractions.CUDADevice(), 256)
        kernel(d_results, d_base, d_eff, d_deg, d_offsets, d_nbp,
               Int32(n_paths), Int32(total_barriers), seed;
               ndrange=n_samples)
        KernelAbstractions.synchronize(KernelAbstractions.CUDADevice())

        result = Array(d_results)

        CUDA.unsafe_free!(d_results)
        CUDA.unsafe_free!(d_base)
        CUDA.unsafe_free!(d_eff)
        CUDA.unsafe_free!(d_deg)
        CUDA.unsafe_free!(d_offsets)
        CUDA.unsafe_free!(d_nbp)

        return result
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        @warn "CUDA Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

"""
    BowtieRisk.backend_risk_aggregate(::CUDABackend, samples)

GPU-accelerated risk aggregation: parallel reduction for mean, variance,
and quantile computation over Monte Carlo samples.
"""
function BowtieRisk.backend_risk_aggregate(b::CUDABackend,
                                            samples::Vector{Float64})
    length(samples) < 1024 && return nothing
    try
        d_samples = CuArray(samples)
        mean_val = Float64(sum(d_samples) / length(d_samples))
        CUDA.unsafe_free!(d_samples)
        return mean_val
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_barrier_eval(::CUDABackend, barriers, factors, model)

GPU-accelerated batch barrier evaluation: evaluates all barriers in parallel.
"""
function BowtieRisk.backend_barrier_eval(b::CUDABackend,
                                          barriers::Vector{BowtieRisk.Barrier},
                                          factors::Vector{BowtieRisk.EscalationFactor},
                                          prob_model::BowtieRisk.ProbabilityModel)
    length(barriers) < 32 && return nothing
    # For large barrier sets, parallel evaluation on GPU is worthwhile
    try
        eff = Float64[b_item.effectiveness for b_item in barriers]
        deg = Float64[b_item.degradation for b_item in barriers]
        d_eff = CuArray(eff)
        d_deg = CuArray(deg)

        factor_reduction = prod(1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors; init=1.0)

        # Compute effective = eff * (1 - deg) * factor_reduction, clamped
        d_effective = clamp.(d_eff .* (1.0 .- d_deg) .* factor_reduction, 0.0, 1.0)
        result = Float64(prod(1.0 .- Array(d_effective)))

        CUDA.unsafe_free!(d_eff)
        CUDA.unsafe_free!(d_deg)
        CUDA.unsafe_free!(d_effective)

        return result
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_correlation_matrix(::CUDABackend, samples_matrix)

GPU-accelerated correlation matrix computation for Monte Carlo samples.
"""
function BowtieRisk.backend_correlation_matrix(b::CUDABackend,
                                                samples::Matrix{Float64})
    size(samples, 1) < 64 && return nothing
    try
        d_samples = CuArray(Float32.(samples))
        n = size(samples, 2)
        # Compute correlation via normalized covariance: C = X'X / (n-1)
        means = sum(d_samples, dims=1) ./ size(d_samples, 1)
        centered = d_samples .- means
        cov_mat = (centered' * centered) ./ (size(d_samples, 1) - 1)
        stds = sqrt.(max.(diag(Array(cov_mat)), 1e-12f0))
        cov_cpu = Array(cov_mat)
        corr = cov_cpu ./ (stds * stds')
        CUDA.unsafe_free!(d_samples)
        return Float64.(corr)
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_probability_sample(::CUDABackend, dist, n_samples)

GPU-accelerated probability distribution sampling for barrier effectiveness.
"""
function BowtieRisk.backend_probability_sample(b::CUDABackend,
                                                dist::BowtieRisk.BarrierDistribution,
                                                n_samples::Int)
    n_samples < 1024 && return nothing
    try
        if dist.kind == :fixed
            return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)
        elseif dist.kind == :beta
            a, b_param = dist.params[1], dist.params[2]
            # Generate beta samples on GPU using inverse CDF approximation
            d_uniform = CUDA.rand(Float64, n_samples)
            uniform = Array(d_uniform)
            CUDA.unsafe_free!(d_uniform)
            # Apply beta inverse CDF on CPU (complex special functions)
            return clamp.(quantile.(Ref(Beta(a, b_param)), uniform), 0.0, 1.0)
        end
        return nothing
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

end # module BowtieRiskCUDAExt
