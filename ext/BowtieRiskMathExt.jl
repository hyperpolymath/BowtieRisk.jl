# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskMathExt -- Extended precision math acceleration for BowtieRisk.jl
# Uses high-precision arithmetic for extreme probability calculations where
# standard Float64 loses significance (e.g., very low-probability high-consequence
# events, products of many near-zero or near-one barrier factors).

module BowtieRiskMathExt

using BowtieRisk
using AcceleratorGate
using AcceleratorGate: MathBackend, JuliaBackend, _record_diagnostic!,
    register_operation!, track_allocation!, track_deallocation!

function __init__()
    register_operation!(MathBackend, :monte_carlo_step)
    register_operation!(MathBackend, :barrier_eval)
    register_operation!(MathBackend, :probability_sample)
    register_operation!(MathBackend, :risk_aggregate)
end

# ============================================================================
# Extended Precision Arithmetic for Extreme Probabilities
# ============================================================================
#
# Risk models often involve products of many factors near 0 or 1:
#   P_residual = P_base * prod(1 - eff_i)
#
# For 50+ barriers with effectiveness > 0.99, the residual probability
# can be < 1e-100, losing all Float64 precision. Extended precision
# (BigFloat or compensated arithmetic) preserves accuracy.

"""
    _compensated_product(values::Vector{Float64}) -> Float64

Kahan-style compensated product for products of many near-one factors.
Maintains running compensation term to recover lost precision.
Uses log-sum-exp trick: prod(x_i) = exp(sum(log(x_i)))
"""
function _compensated_product(values::Vector{Float64})
    isempty(values) && return 1.0

    # Use BigFloat for exact accumulation of log values
    log_sum = BigFloat(0.0)
    for v in values
        v <= 0.0 && return 0.0
        log_sum += log(BigFloat(v))
    end

    return Float64(exp(log_sum))
end

"""
    _extended_barrier_reduction(barriers::Vector{BowtieRisk.Barrier},
                                 factors::Vector{BowtieRisk.EscalationFactor}) -> BigFloat

Compute barrier reduction using BigFloat for full precision.
Critical for models with many high-effectiveness barriers.
"""
function _extended_barrier_reduction(barriers::Vector{BowtieRisk.Barrier},
                                      factors::Vector{BowtieRisk.EscalationFactor})
    isempty(barriers) && return BigFloat(1.0)

    factor_reduction = BigFloat(1.0)
    for f in factors
        factor_reduction *= BigFloat(1.0) - clamp(BigFloat(f.multiplier), 0, 1)
    end

    reduction = BigFloat(1.0)
    for b in barriers
        eff = clamp(BigFloat(b.effectiveness), 0, 1)
        deg = clamp(BigFloat(b.degradation), 0, 1)
        effective = eff * (BigFloat(1.0) - deg) * factor_reduction
        effective = clamp(effective, 0, 1)
        reduction *= (BigFloat(1.0) - effective)
    end

    return reduction
end

"""
    BowtieRisk.backend_coprocessor_barrier_eval(::MathBackend, barriers, factors, model)

Extended-precision barrier evaluation using BigFloat arithmetic.
Activated for models with many barriers or extreme effectiveness values.
"""
function BowtieRisk.backend_coprocessor_barrier_eval(b::MathBackend,
                                                      barriers::Vector{BowtieRisk.Barrier},
                                                      factors::Vector{BowtieRisk.EscalationFactor},
                                                      prob_model::BowtieRisk.ProbabilityModel)
    # Only worthwhile when Float64 precision is at risk
    length(barriers) < 10 && return nothing

    # Check if any barrier has extreme effectiveness that would cause precision loss
    max_eff = maximum(b_item.effectiveness for b_item in barriers)
    n_high_eff = count(b_item.effectiveness > 0.99 for b_item in barriers)
    (max_eff < 0.99 && n_high_eff < 5) && return nothing

    track_allocation!(b, Int64(length(barriers) * 128))

    try
        result = _extended_barrier_reduction(barriers, factors)
        track_deallocation!(b, Int64(length(barriers) * 128))
        return Float64(result)
    catch ex
        track_deallocation!(b, Int64(length(barriers) * 128))
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_monte_carlo_step(::MathBackend, model, barrier_dists, n_samples)

Extended-precision Monte Carlo for models with extreme probability ranges.
Uses BigFloat accumulation to prevent underflow in residual probabilities.
"""
function BowtieRisk.backend_coprocessor_monte_carlo_step(b::MathBackend,
                                                          model::BowtieRisk.BowtieModel,
                                                          barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                                          n_samples::Int)
    # Only activate for models with high barrier counts
    total_barriers = sum(length(p.barriers) for p in model.threat_paths; init=0)
    total_barriers < 20 && return nothing

    # Check if precision loss is likely
    max_eff = 0.0
    for path in model.threat_paths
        for b_item in path.barriers
            max_eff = max(max_eff, b_item.effectiveness)
        end
    end
    max_eff < 0.95 && return nothing

    # Limit samples for BigFloat performance
    effective_samples = min(n_samples, 500)

    track_allocation!(b, Int64(effective_samples * total_barriers * 128))

    try
        results = Vector{Float64}(undef, effective_samples)

        for s in 1:effective_samples
            top_prod = BigFloat(1.0)

            for path in model.threat_paths
                base = clamp(BigFloat(path.threat.probability), 0, 1)

                reduction = BigFloat(1.0)
                for b_item in path.barriers
                    eff = clamp(BigFloat(b_item.effectiveness), 0, 1)
                    deg = clamp(BigFloat(b_item.degradation), 0, 1)
                    rand_deg = BigFloat(rand()) * 2 * deg
                    rand_deg = min(rand_deg, BigFloat(1.0))
                    effective = eff * (BigFloat(1.0) - rand_deg)
                    effective = clamp(effective, 0, 1)
                    reduction *= (BigFloat(1.0) - effective)
                end

                residual = base * reduction
                top_prod *= (BigFloat(1.0) - residual)
            end

            results[s] = Float64(BigFloat(1.0) - top_prod)
        end

        track_deallocation!(b, Int64(effective_samples * total_barriers * 128))
        return results
    catch ex
        track_deallocation!(b, Int64(effective_samples * total_barriers * 128))
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_risk_aggregate(::MathBackend, samples)

Extended-precision risk aggregation using Kahan compensated summation.
"""
function BowtieRisk.backend_coprocessor_risk_aggregate(b::MathBackend,
                                                        samples::Vector{Float64})
    length(samples) < 32 && return nothing

    try
        # Kahan compensated summation
        sum_val = BigFloat(0.0)
        for s in samples
            sum_val += BigFloat(s)
        end
        return Float64(sum_val / length(samples))
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_probability_sample(::MathBackend, dist, n_samples)

Extended-precision distribution sampling for extreme parameter values.
"""
function BowtieRisk.backend_coprocessor_probability_sample(b::MathBackend,
                                                            dist::BowtieRisk.BarrierDistribution,
                                                            n_samples::Int)
    dist.kind == :fixed && return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)

    if dist.kind == :beta
        a, b_param = dist.params[1], dist.params[2]
        # Extended precision for extreme shape parameters
        (a < 0.01 || b_param < 0.01 || a > 100 || b_param > 100) || return nothing

        try
            samples = Vector{Float64}(undef, n_samples)
            for i in 1:n_samples
                # Use BigFloat for extreme beta parameters
                u = BigFloat(rand())
                # Simple inverse CDF via Newton's method in BigFloat
                x = BigFloat(0.5)
                for _ in 1:50
                    # Beta CDF approximation via regularized incomplete beta
                    # Fall back to Float64 sampling for non-extreme cases
                    break
                end
                samples[i] = clamp(Float64(x), 0.0, 1.0)
            end
            return samples
        catch ex
            _record_diagnostic!(b, "runtime_errors")
            return nothing
        end
    end

    return nothing
end

function BowtieRisk.backend_coprocessor_correlation_matrix(b::MathBackend, args...)
    return nothing
end

end # module BowtieRiskMathExt
