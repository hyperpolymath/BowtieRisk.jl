# SPDX-License-Identifier: MPL-2.0
# (MPL-2.0 preferred; MPL-2.0 required for Julia ecosystem)
# Property-based tests for BowtieRisk.jl
# Verifies key risk-modelling invariants across randomly generated scenarios.

using Test
using BowtieRisk

@testset "Property-Based Tests" begin

    @testset "Invariant: top event probability in [0, 1]" begin
        for _ in 1:50
            n_threats = rand(1:5)
            threat_paths = [
                ThreatPath(
                    Threat(Symbol("T$i"), rand(), "Threat $i"),
                    [Barrier(Symbol("B$i"), rand(), :preventive, "B", 0.0, :none)],
                    EscalationFactor[],
                )
                for i in 1:n_threats
            ]
            model = BowtieModel(
                Hazard(:H, "H"), TopEvent(:T, "T"),
                threat_paths,
                [ConsequencePath(Consequence(:C, rand(), "C"), Barrier[], EscalationFactor[])],
                ProbabilityModel(:independent),
            )
            s = evaluate(model)
            @test 0.0 <= s.top_event_probability <= 1.0
        end
    end

    @testset "Invariant: adding a perfect barrier cannot increase risk" begin
        for _ in 1:50
            p_threat = rand(0.01:0.01:0.5)
            threat = Threat(:T, p_threat, "Threat")
            cons   = ConsequencePath(Consequence(:C, 0.5, "C"), Barrier[], EscalationFactor[])

            model_bare = BowtieModel(
                Hazard(:H, "H"), TopEvent(:Top, "Top"),
                [ThreatPath(threat, Barrier[], EscalationFactor[])],
                [cons], ProbabilityModel(:independent),
            )
            model_with = BowtieModel(
                Hazard(:H, "H"), TopEvent(:Top, "Top"),
                [ThreatPath(threat, [Barrier(:B, 1.0, :preventive, "Perfect", 0.0, :none)], EscalationFactor[])],
                [cons], ProbabilityModel(:independent),
            )

            s_bare = evaluate(model_bare)
            s_with = evaluate(model_with)

            # A perfect barrier always eliminates risk
            @test s_with.top_event_probability <= s_bare.top_event_probability
            @test s_with.top_event_probability ≈ 0.0
        end
    end

    @testset "Invariant: consequence risks are non-negative" begin
        for _ in 1:50
            n_cons = rand(1:4)
            cons_paths = [
                ConsequencePath(
                    Consequence(Symbol("C$i"), rand(), "C $i"),
                    [Barrier(Symbol("M$i"), rand(), :mitigative, "M", 0.0, :none)],
                    EscalationFactor[],
                )
                for i in 1:n_cons
            ]
            model = BowtieModel(
                Hazard(:H, "H"), TopEvent(:T, "T"),
                [ThreatPath(Threat(:T1, rand(), "T1"), Barrier[], EscalationFactor[])],
                cons_paths,
                ProbabilityModel(:independent),
            )
            s = evaluate(model)
            for (_, v) in s.consequence_risks
                @test v >= 0.0
            end
        end
    end

    @testset "Invariant: more barriers cannot increase threat residual" begin
        for _ in 1:50
            p = rand(0.05:0.05:0.5)
            threat = Threat(:T, p, "Threat")
            eff1 = rand(0.3:0.1:0.9)
            eff2 = rand(0.3:0.1:0.9)
            cons = ConsequencePath(Consequence(:C, 0.5, "C"), Barrier[], EscalationFactor[])

            model_one = BowtieModel(
                Hazard(:H, "H"), TopEvent(:Top, "Top"),
                [ThreatPath(threat, [Barrier(:B1, eff1, :preventive, "B1", 0.0, :none)], EscalationFactor[])],
                [cons], ProbabilityModel(:independent),
            )
            model_two = BowtieModel(
                Hazard(:H, "H"), TopEvent(:Top, "Top"),
                [ThreatPath(threat, [Barrier(:B1, eff1, :preventive, "B1", 0.0, :none),
                                     Barrier(:B2, eff2, :preventive, "B2", 0.0, :none)], EscalationFactor[])],
                [cons], ProbabilityModel(:independent),
            )

            s_one = evaluate(model_one)
            s_two = evaluate(model_two)

            @test s_two.threat_residuals[:T] <= s_one.threat_residuals[:T] + 1e-12
        end
    end

    @testset "Invariant: simulation mean converges toward deterministic estimate" begin
        # Use a fixed, simple model and verify mean is in a reasonable range
        for _ in 1:50
            p = rand(0.1:0.05:0.4)
            eff = rand(0.3:0.1:0.8)
            model = BowtieModel(
                Hazard(:H, "H"), TopEvent(:T, "T"),
                [ThreatPath(Threat(:T1, p, "T1"), [Barrier(:B1, eff, :preventive, "B1", 0.0, :none)], EscalationFactor[])],
                [ConsequencePath(Consequence(:C, 0.5, "C"), Barrier[], EscalationFactor[])],
                ProbabilityModel(:independent),
            )
            det = evaluate(model)
            sim = simulate(model; samples=50, barrier_dists=Dict{Symbol,BarrierDistribution}())
            # Nominal simulation should match deterministic within ±0.3
            @test abs(sim.top_event_mean - det.top_event_probability) < 0.3
        end
    end

end
