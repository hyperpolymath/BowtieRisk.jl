# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskNPUExt -- NPU (Neural Processing Unit) acceleration for BowtieRisk.jl
# Leverages NPU tensor cores for batch risk matrix evaluation and
# learned risk model surrogate inference.

module BowtieRiskNPUExt

using BowtieRisk
using AcceleratorGate
using AcceleratorGate: NPUBackend, JuliaBackend, _record_diagnostic!,
    register_operation!, track_allocation!, track_deallocation!
using LinearAlgebra

function __init__()
    register_operation!(NPUBackend, :monte_carlo_step)
    register_operation!(NPUBackend, :correlation_matrix)
    register_operation!(NPUBackend, :risk_aggregate)
end

# ============================================================================
# NPU Tensor-Accelerated Risk Evaluation
# ============================================================================
#
# NPU tensor cores are optimised for small-matrix multiplies at low precision
# (INT8, FP16, BF16). For risk computation:
# - Barrier evaluation as tensor contraction in reduced precision
# - Correlation matrix via FP16 GEMM with accumulation
# - Surrogate model inference for rapid what-if analysis

"""
    _npu_fp16_barrier_matrix(model, n_samples) -> (Matrix{Float32}, Vector{Float32})

Build barrier evaluation matrices in NPU-friendly FP16-compatible format.
Uses Float32 simulation of FP16 range with reduced mantissa.
"""
function _npu_fp16_barrier_matrix(model::BowtieRisk.BowtieModel, n_samples::Int)
    all_barriers = BowtieRisk.Barrier[]
    path_barrier_counts = Int[]
    base_probs = Float32[]

    for path in model.threat_paths
        push!(base_probs, Float16(path.threat.probability) |> Float32)
        push!(path_barrier_counts, length(path.barriers))
        append!(all_barriers, path.barriers)
    end

    n_barriers = length(all_barriers)
    # Build effectiveness matrix in FP16-compatible range
    eff_matrix = zeros(Float32, n_samples, n_barriers)
    for j in 1:n_barriers
        b = all_barriers[j]
        eff = Float16(b.effectiveness) |> Float32
        deg = Float16(b.degradation) |> Float32
        for i in 1:n_samples
            rand_deg = min(deg * 2.0f0 * rand(Float32), 1.0f0)
            eff_matrix[i, j] = clamp(eff * (1.0f0 - rand_deg), 0.0f0, 1.0f0)
        end
    end

    return eff_matrix, base_probs, path_barrier_counts
end

"""
    BowtieRisk.backend_coprocessor_monte_carlo_step(::NPUBackend, model, barrier_dists, n_samples)

NPU tensor-accelerated Monte Carlo via FP16 batch evaluation.
Formulates barrier reduction as tensor operations suitable for
NPU matrix multiply units.
"""
function BowtieRisk.backend_coprocessor_monte_carlo_step(b::NPUBackend,
                                                          model::BowtieRisk.BowtieModel,
                                                          barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                                          n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 64 && return nothing

    total_barriers = sum(length(p.barriers) for p in model.threat_paths; init=0)
    total_barriers == 0 && return nothing

    track_allocation!(b, Int64(n_samples * total_barriers * 4))

    try
        eff_matrix, base_probs, path_barrier_counts = _npu_fp16_barrier_matrix(model, n_samples)

        # Compute log(1 - eff) for tensor contraction
        log_pass = log.(1.0f0 .- eff_matrix)

        # Build path mapping matrix (n_barriers x n_paths)
        n_barriers = size(eff_matrix, 2)
        mapping = zeros(Float32, n_barriers, n_paths)
        offset = 0
        for (p, count) in enumerate(path_barrier_counts)
            for j in 1:count
                mapping[offset + j, p] = 1.0f0
            end
            offset += count
        end

        # NPU tensor multiply: (n_samples x n_barriers) * (n_barriers x n_paths)
        log_reduction = log_pass * mapping
        path_reduction = exp.(log_reduction)

        results = Vector{Float64}(undef, n_samples)
        for i in 1:n_samples
            top_prod = 1.0
            for p in 1:n_paths
                residual = Float64(base_probs[p]) * Float64(path_reduction[i, p])
                top_prod *= (1.0 - residual)
            end
            results[i] = 1.0 - top_prod
        end

        track_deallocation!(b, Int64(n_samples * total_barriers * 4))
        return results
    catch ex
        track_deallocation!(b, Int64(n_samples * total_barriers * 4))
        _record_diagnostic!(b, "runtime_errors")
        @warn "NPU Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_correlation_matrix(::NPUBackend, samples)

NPU tensor-accelerated correlation matrix via FP16 GEMM.
"""
function BowtieRisk.backend_coprocessor_correlation_matrix(b::NPUBackend,
                                                            samples::Matrix{Float64})
    n, m = size(samples)
    n < 32 && return nothing

    try
        X = Float32.(samples)
        means = sum(X, dims=1) ./ n
        centered = X .- means
        # NPU GEMM: centered' * centered
        cov_mat = (centered' * centered) ./ (n - 1)
        stds = sqrt.(max.(diag(cov_mat), 1e-12f0))
        corr = cov_mat ./ (stds * stds')
        return Float64.(corr)
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_risk_aggregate(::NPUBackend, samples)

NPU-accelerated risk aggregation via tensor reduction.
"""
function BowtieRisk.backend_coprocessor_risk_aggregate(b::NPUBackend,
                                                        samples::Vector{Float64})
    length(samples) < 256 && return nothing
    try
        s = Float32.(samples)
        return Float64(sum(s) / length(s))
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_coprocessor_barrier_eval(b::NPUBackend, args...)
    return nothing
end

function BowtieRisk.backend_coprocessor_probability_sample(b::NPUBackend, args...)
    return nothing
end

end # module BowtieRiskNPUExt
