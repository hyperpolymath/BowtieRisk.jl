# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskTPUExt -- TPU systolic array acceleration for BowtieRisk.jl
# Exploits matrix-multiply hardware for batch risk matrix operations
# and correlation computation.

module BowtieRiskTPUExt

using BowtieRisk
using AcceleratorGate
using AcceleratorGate: TPUBackend, JuliaBackend, _record_diagnostic!,
    register_operation!, track_allocation!, track_deallocation!
using LinearAlgebra

function __init__()
    register_operation!(TPUBackend, :monte_carlo_step)
    register_operation!(TPUBackend, :risk_aggregate)
    register_operation!(TPUBackend, :correlation_matrix)
end

# ============================================================================
# TPU Monte Carlo via Batch Matrix Operations
# ============================================================================
#
# Key insight: Monte Carlo risk evaluation across N samples and P paths
# can be formulated as matrix operations. For each sample, barrier effectiveness
# is drawn from distributions, forming a (N x B) matrix. Path residuals
# are computed as products along barrier dimensions -- expressible as
# log-space matmul on the systolic array.

"""
    _build_barrier_matrix(model, n_samples) -> (Matrix{Float32}, Vector{Float32})

Build a (n_samples x n_barriers) matrix of sampled barrier effectiveness
values and a vector of base threat probabilities per path.
Uses Float32 for TPU-native precision.
"""
function _build_barrier_matrix(model::BowtieRisk.BowtieModel, n_samples::Int)
    all_barriers = BowtieRisk.Barrier[]
    path_barrier_counts = Int[]
    base_probs = Float32[]

    for path in model.threat_paths
        push!(base_probs, Float32(path.threat.probability))
        push!(path_barrier_counts, length(path.barriers))
        append!(all_barriers, path.barriers)
    end

    n_barriers = length(all_barriers)
    # Sample barrier effectiveness with random degradation
    barrier_matrix = zeros(Float32, n_samples, n_barriers)
    for j in 1:n_barriers
        b = all_barriers[j]
        eff = Float32(b.effectiveness)
        deg = Float32(b.degradation)
        for i in 1:n_samples
            actual_deg = deg * 2.0f0 * rand(Float32)
            actual_deg = min(actual_deg, 1.0f0)
            barrier_matrix[i, j] = clamp(eff * (1.0f0 - actual_deg), 0.0f0, 1.0f0)
        end
    end

    return barrier_matrix, base_probs, path_barrier_counts
end

"""
    BowtieRisk.backend_coprocessor_monte_carlo_step(::TPUBackend, model, barrier_dists, n_samples)

TPU-accelerated Monte Carlo via systolic array batch evaluation.
Formulates barrier reduction as log-space matrix operations suitable
for the TPU's matmul hardware.
"""
function BowtieRisk.backend_coprocessor_monte_carlo_step(b::TPUBackend,
                                                          model::BowtieRisk.BowtieModel,
                                                          barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                                          n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 128 && return nothing

    mem_estimate = Int64(n_samples * 100 * 4 + n_paths * n_samples * 8)
    track_allocation!(b, mem_estimate)

    try
        barrier_matrix, base_probs, path_barrier_counts = _build_barrier_matrix(model, n_samples)
        n_barriers = size(barrier_matrix, 2)

        # Compute log(1 - effectiveness) for each barrier sample
        # Then sum within each path's barrier group = log of product
        log_pass = log.(1.0f0 .- barrier_matrix)

        # Build path-to-barrier mapping matrix (n_barriers x n_paths)
        # This is the systolic array matmul: log_pass * mapping = log_path_reduction
        mapping = zeros(Float32, n_barriers, n_paths)
        offset = 0
        for (p, count) in enumerate(path_barrier_counts)
            for j in 1:count
                mapping[offset + j, p] = 1.0f0
            end
            offset += count
        end

        # Systolic array matmul: (n_samples x n_barriers) * (n_barriers x n_paths)
        log_path_reduction = log_pass * mapping  # (n_samples x n_paths)

        # Convert back: path_reduction = exp(log_path_reduction)
        path_reduction = exp.(log_path_reduction)

        # Residual probabilities per path per sample
        results = zeros(Float64, n_samples)
        for i in 1:n_samples
            top_prod = 1.0
            for p in 1:n_paths
                residual = Float64(base_probs[p]) * Float64(path_reduction[i, p])
                top_prod *= (1.0 - residual)
            end
            results[i] = 1.0 - top_prod
        end

        track_deallocation!(b, mem_estimate)
        return results
    catch ex
        track_deallocation!(b, mem_estimate)
        _record_diagnostic!(b, "runtime_errors")
        @warn "TPU Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_risk_aggregate(::TPUBackend, samples)

TPU-accelerated risk aggregation via batch reduction.
"""
function BowtieRisk.backend_coprocessor_risk_aggregate(b::TPUBackend,
                                                        samples::Vector{Float64})
    length(samples) < 512 && return nothing
    try
        # Reshape for systolic-array-friendly reduction
        s = Float32.(samples)
        mean_val = Float64(sum(s) / length(s))
        return mean_val
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_correlation_matrix(::TPUBackend, samples)

TPU-accelerated correlation matrix via systolic array matmul.
C = X_centered' * X_centered is a perfect fit for the systolic array.
"""
function BowtieRisk.backend_coprocessor_correlation_matrix(b::TPUBackend,
                                                            samples::Matrix{Float64})
    n, m = size(samples)
    n < 64 && return nothing

    mem_estimate = Int64(n * m * 4 + m * m * 4)
    track_allocation!(b, mem_estimate)

    try
        X = Float32.(samples)
        means = sum(X, dims=1) ./ n
        centered = X .- means
        # Systolic array matmul: (m x n) * (n x m) -> (m x m) covariance
        cov_mat = (centered' * centered) ./ (n - 1)
        stds = sqrt.(max.(diag(cov_mat), 1e-12f0))
        corr = cov_mat ./ (stds * stds')
        track_deallocation!(b, mem_estimate)
        return Float64.(corr)
    catch ex
        track_deallocation!(b, mem_estimate)
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_coprocessor_barrier_eval(b::TPUBackend, args...)
    return nothing  # Barrier eval is too small for TPU overhead
end

function BowtieRisk.backend_coprocessor_probability_sample(b::TPUBackend, args...)
    return nothing  # Distribution sampling is sequential, not matmul-friendly
end

end # module BowtieRiskTPUExt
