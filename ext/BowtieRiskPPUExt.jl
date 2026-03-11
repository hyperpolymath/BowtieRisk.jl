# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# BowtieRiskPPUExt -- PPU (Probabilistic Processing Unit) acceleration for BowtieRisk.jl
# Native probabilistic computation hardware for stochastic risk modelling:
# - Hardware-native probability distributions
# - Probabilistic circuits for barrier failure propagation
# - Bayesian network evaluation in hardware

module BowtieRiskPPUExt

using BowtieRisk
using AcceleratorGate
using AcceleratorGate: PPUBackend, JuliaBackend, _record_diagnostic!,
    register_operation!, track_allocation!, track_deallocation!

function __init__()
    register_operation!(PPUBackend, :monte_carlo_step)
    register_operation!(PPUBackend, :probability_sample)
    register_operation!(PPUBackend, :barrier_eval)
end

# ============================================================================
# PPU Probabilistic Circuit Evaluation
# ============================================================================
#
# PPU hardware natively represents probability distributions and computes
# with stochastic bit streams. A "probabilistic circuit" is a DAG where
# each node represents a random variable and edges encode dependencies.
# The bowtie model maps naturally to this:
# - Threats: Bernoulli sources
# - Barriers: conditional probability gates
# - Top event: OR-combination circuit
# - Consequences: conditional severity gates

"""
    _stochastic_bitstream(probability::Float64, length::Int) -> BitVector

Generate a stochastic bitstream where the density of 1s equals the probability.
PPU hardware generates these natively; we simulate with PRNG.
"""
function _stochastic_bitstream(probability::Float64, length::Int)
    p = clamp(probability, 0.0, 1.0)
    return BitVector(rand() < p for _ in 1:length)
end

"""
    _and_bitstream(a::BitVector, b::BitVector) -> BitVector

Bitwise AND of two stochastic bitstreams.
Computes P(A AND B) = P(A) * P(B) for independent streams.
"""
_and_bitstream(a::BitVector, b::BitVector) = a .& b

"""
    _or_bitstream(a::BitVector, b::BitVector) -> BitVector

Bitwise OR of two stochastic bitstreams.
Computes P(A OR B) = 1 - (1-P(A))*(1-P(B)) for independent streams.
"""
_or_bitstream(a::BitVector, b::BitVector) = a .| b

"""
    _not_bitstream(a::BitVector) -> BitVector

Bitwise NOT of a stochastic bitstream.
"""
_not_bitstream(a::BitVector) = .!a

"""
    _bitstream_probability(stream::BitVector) -> Float64

Estimate probability from bitstream density.
"""
_bitstream_probability(stream::BitVector) = sum(stream) / length(stream)

"""
    BowtieRisk.backend_coprocessor_monte_carlo_step(::PPUBackend, model, barrier_dists, n_samples)

PPU stochastic bitstream evaluation of the bowtie model.
Each sample is a bit position in the stochastic bitstreams;
the full Monte Carlo is computed in a single pass through the
probabilistic circuit.
"""
function BowtieRisk.backend_coprocessor_monte_carlo_step(b::PPUBackend,
                                                          model::BowtieRisk.BowtieModel,
                                                          barrier_dists::Dict{Symbol, BowtieRisk.BarrierDistribution},
                                                          n_samples::Int)
    n_paths = length(model.threat_paths)
    n_samples < 64 && return nothing

    # Align to machine word for efficient bitwise ops
    stream_length = ((n_samples + 63) >> 6) << 6

    track_allocation!(b, Int64(stream_length * n_paths * 4))

    try
        # Initialize top-event stream as all-zero (no event)
        top_event_stream = falses(stream_length)

        for path in model.threat_paths
            # Threat source: Bernoulli bitstream
            threat_stream = _stochastic_bitstream(path.threat.probability, stream_length)

            # Each barrier reduces the threat
            residual_stream = threat_stream
            for barrier in path.barriers
                eff = barrier.effectiveness * (1.0 - barrier.degradation)
                # Apply escalation factors
                for factor in path.escalation_factors
                    eff *= (1.0 - clamp(factor.multiplier, 0.0, 1.0))
                end
                eff = clamp(eff, 0.0, 1.0)

                # Barrier blocks the threat with probability = effectiveness
                barrier_blocks = _stochastic_bitstream(eff, stream_length)
                # Residual = threat AND NOT(barrier_blocks)
                residual_stream = _and_bitstream(residual_stream, _not_bitstream(barrier_blocks))
            end

            # Top event = OR of all path residuals
            top_event_stream = _or_bitstream(top_event_stream, residual_stream)
        end

        # Extract per-sample results from bitstream
        results = Vector{Float64}(undef, n_samples)
        for i in 1:n_samples
            results[i] = top_event_stream[i] ? 1.0 : 0.0
        end

        track_deallocation!(b, Int64(stream_length * n_paths * 4))
        return results
    catch ex
        track_deallocation!(b, Int64(stream_length * n_paths * 4))
        _record_diagnostic!(b, "runtime_errors")
        @warn "PPU Monte Carlo failed, falling back to CPU" exception=ex maxlog=1
        return nothing
    end
end

"""
    BowtieRisk.backend_coprocessor_probability_sample(::PPUBackend, dist, n_samples)

PPU native probability distribution sampling via stochastic bitstreams.
"""
function BowtieRisk.backend_coprocessor_probability_sample(b::PPUBackend,
                                                            dist::BowtieRisk.BarrierDistribution,
                                                            n_samples::Int)
    dist.kind == :fixed && return fill(clamp(dist.params[1], 0.0, 1.0), n_samples)

    if dist.kind == :triangular
        try
            low, mode, high = dist.params
            (low <= mode <= high && low < high) || return nothing
            # PPU can generate triangular distributions natively via
            # max/min of two uniform bitstreams
            samples = Vector{Float64}(undef, n_samples)
            for i in 1:n_samples
                u = rand()
                c = (mode - low) / (high - low)
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

"""
    BowtieRisk.backend_coprocessor_barrier_eval(::PPUBackend, barriers, factors, model)

PPU probabilistic circuit barrier evaluation.
"""
function BowtieRisk.backend_coprocessor_barrier_eval(b::PPUBackend,
                                                      barriers::Vector{BowtieRisk.Barrier},
                                                      factors::Vector{BowtieRisk.EscalationFactor},
                                                      prob_model::BowtieRisk.ProbabilityModel)
    isempty(barriers) && return nothing

    try
        stream_length = 10000  # High precision via long bitstream
        factor_reduction = prod(1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors; init=1.0)

        # Probabilistic circuit: product of (1 - eff_i) via AND of NOT streams
        pass_stream = trues(stream_length)

        for barrier in barriers
            eff = clamp(barrier.effectiveness * (1.0 - barrier.degradation) * factor_reduction, 0.0, 1.0)
            barrier_pass = _stochastic_bitstream(1.0 - eff, stream_length)
            pass_stream = _and_bitstream(pass_stream, barrier_pass)
        end

        return _bitstream_probability(pass_stream)
    catch ex
        _record_diagnostic!(b, "runtime_errors")
        return nothing
    end
end

function BowtieRisk.backend_coprocessor_risk_aggregate(b::PPUBackend, args...)
    return nothing
end

function BowtieRisk.backend_coprocessor_correlation_matrix(b::PPUBackend, args...)
    return nothing
end

end # module BowtieRiskPPUExt
