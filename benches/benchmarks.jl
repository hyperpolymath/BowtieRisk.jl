# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# BenchmarkTools benchmarks for BowtieRisk.jl
# Measures evaluate, simulate, and sensitivity_tornado on small/medium/large models.

using BenchmarkTools
using BowtieRisk

# ── Helper: build a model of the requested scale ──────────────────────────────

function make_model(n_threats::Int, n_barriers_each::Int, n_consequences::Int)
    threat_paths = [
        ThreatPath(
            Threat(Symbol("t$i"), 0.01 * i, "Threat $i"),
            [Barrier(Symbol("b$(i)_$j"), 0.5 + 0.05j, :preventive, "B", 0.0, :none)
             for j in 1:n_barriers_each],
            EscalationFactor[],
        )
        for i in 1:n_threats
    ]
    consequence_paths = [
        ConsequencePath(
            Consequence(Symbol("c$i"), 0.1 * i, "Consequence $i"),
            [Barrier(Symbol("mb$(i)_$j"), 0.6 + 0.05j, :mitigative, "MB", 0.0, :none)
             for j in 1:2],
            EscalationFactor[],
        )
        for i in 1:n_consequences
    ]
    BowtieModel(
        Hazard(:BigHazard, "Hazard"),
        TopEvent(:BigEvent, "Top event"),
        threat_paths, consequence_paths,
        ProbabilityModel(:independent),
    )
end

small_model  = make_model(3,  2, 2)   # 3 threats, 2 barriers each, 2 consequences
medium_model = make_model(10, 5, 5)   # 10 threats, 5 barriers each, 5 consequences
large_model  = make_model(25, 8, 10)  # 25 threats, 8 barriers each, 10 consequences

# Warm up
evaluate(small_model); evaluate(medium_model); evaluate(large_model)

# ── evaluate benchmarks ───────────────────────────────────────────────────────

println("=== evaluate (small: 3 threats) ===")
@benchmark evaluate($small_model)

println("=== evaluate (medium: 10 threats) ===")
@benchmark evaluate($medium_model)

println("=== evaluate (large: 25 threats) ===")
@benchmark evaluate($large_model)

# ── simulate benchmarks ───────────────────────────────────────────────────────

empty_dists = Dict{Symbol, BarrierDistribution}()

println("=== simulate (small: 500 samples) ===")
@benchmark simulate($small_model; samples=500, barrier_dists=$empty_dists)

println("=== simulate (medium: 1000 samples) ===")
@benchmark simulate($medium_model; samples=1000, barrier_dists=$empty_dists)

println("=== simulate (large: 2000 samples) ===")
@benchmark simulate($large_model; samples=2000, barrier_dists=$empty_dists)

# ── sensitivity_tornado benchmarks ───────────────────────────────────────────

println("=== sensitivity_tornado (small) ===")
@benchmark sensitivity_tornado($small_model; delta=0.1)

println("=== sensitivity_tornado (medium) ===")
@benchmark sensitivity_tornado($medium_model; delta=0.1)

println("=== sensitivity_tornado (large) ===")
@benchmark sensitivity_tornado($large_model; delta=0.1)
