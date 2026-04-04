# SPDX-License-Identifier: MPL-2.0
# (PMPL-1.0-or-later preferred; MPL-2.0 required for Julia ecosystem)
# E2E pipeline tests for BowtieRisk.jl
# Tests full bowtie model lifecycle: build → evaluate → simulate → export → round-trip.

using Test
using BowtieRisk

@testset "E2E Pipeline Tests" begin

    @testset "Full pipeline: cyber security scenario" begin
        # 1. Define hazard and top event
        hazard = Hazard(:DataExfiltration, "Sensitive data leaves the network")
        top_event = TopEvent(:Breach, "Successful intrusion")

        # 2. Build threat paths with barriers
        threat_paths = [
            ThreatPath(
                Threat(:Phishing, 0.15, "Spear phishing email"),
                [
                    Barrier(:EmailFilter, 0.7, :preventive, "Email gateway filter", 0.05, :none),
                    Barrier(:UserTraining, 0.5, :preventive, "Security awareness training", 0.1, :shared_training),
                ],
                [EscalationFactor(:RemoteWork, 0.2, "Reduced physical oversight")],
            ),
            ThreatPath(
                Threat(:InsiderThreat, 0.05, "Malicious insider"),
                [Barrier(:RBAC, 0.8, :preventive, "Role-based access control", 0.0, :none)],
                EscalationFactor[],
            ),
        ]

        # 3. Build consequence paths
        consequence_paths = [
            ConsequencePath(
                Consequence(:DataLoss, 0.9, "Customer PII exfiltrated"),
                [
                    Barrier(:DLP, 0.6, :mitigative, "Data loss prevention", 0.0, :none),
                    Barrier(:Encryption, 0.9, :mitigative, "Data at rest encryption", 0.0, :none),
                ],
                EscalationFactor[],
            ),
            ConsequencePath(
                Consequence(:Reputational, 0.7, "Public disclosure required"),
                Barrier[],
                EscalationFactor[],
            ),
        ]

        # 4. Build model
        model = BowtieModel(hazard, top_event, threat_paths, consequence_paths,
                             ProbabilityModel(:independent))

        # 5. Evaluate deterministically
        summary = evaluate(model)
        @test 0.0 < summary.top_event_probability < 1.0
        @test haskey(summary.threat_residuals, :Phishing)
        @test haskey(summary.threat_residuals, :InsiderThreat)
        @test haskey(summary.consequence_risks, :DataLoss)
        @test haskey(summary.consequence_risks, :Reputational)
        # Barriers reduce threats below raw probability
        @test summary.threat_residuals[:Phishing] < 0.15
        @test summary.threat_residuals[:InsiderThreat] < 0.05

        # 6. Monte Carlo simulation
        dists = Dict(
            :EmailFilter   => BarrierDistribution(:beta, (5.0, 2.0, 0.0)),
            :UserTraining  => BarrierDistribution(:triangular, (0.2, 0.5, 0.8)),
            :Encryption    => BarrierDistribution(:beta, (8.0, 1.0, 0.0)),
        )
        sim = simulate(model; samples=200, barrier_dists=dists)
        @test sim.top_event_mean >= 0.0
        @test length(sim.samples) == 200

        # 7. Sensitivity
        tornado = sensitivity_tornado(model; delta=0.1)
        @test !isempty(tornado)
        impacts = [abs(t[3] - t[2]) for t in tornado]
        @test issorted(impacts, rev=true)

        # 8. Export round-trip
        dir = mktempdir()
        model_path = joinpath(dir, "model.json")
        write_model_json(model_path, model)
        model2 = read_model_json(model_path)
        summary2 = evaluate(model2)
        @test summary2.top_event_probability ≈ summary.top_event_probability

        # 9. Diagram exports
        mermaid = to_mermaid(model)
        dot     = to_graphviz(model)
        @test occursin("DataExfiltration", mermaid)
        @test occursin("digraph", dot)
    end

    @testset "Error handling: invalid configurations" begin
        # Unknown template
        @test_throws ErrorException template_model(:unknown_template_xyz)

        # Unknown probability model
        bad_model = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(Threat(:X, 0.1, "Threat"), Barrier[], EscalationFactor[])],
            [ConsequencePath(Consequence(:C, 0.5, "Cons"), Barrier[], EscalationFactor[])],
            ProbabilityModel(:bogus_mode),
        )
        @test_throws ErrorException evaluate(bad_model)

        # Unknown barrier distribution in simulation
        simple_model = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(Threat(:X, 0.1, "Threat"), [Barrier(:B, 0.5, :preventive, "B", 0.0, :none)], EscalationFactor[])],
            [ConsequencePath(Consequence(:C, 0.5, "Cons"), Barrier[], EscalationFactor[])],
            ProbabilityModel(:independent),
        )
        @test_throws ErrorException simulate(simple_model; samples=5,
            barrier_dists=Dict(:B => BarrierDistribution(:no_such_dist, (0.5, 0.5, 0.5))))
    end

    @testset "Round-trip consistency: JSON serialisation" begin
        # Use the built-in process_safety template
        model = template_model(:process_safety)
        summary = evaluate(model)

        dir = mktempdir()
        path = joinpath(dir, "ps.json")
        write_model_json(path, model)
        model2 = read_model_json(path)
        summary2 = evaluate(model2)

        @test summary2.top_event_probability ≈ summary.top_event_probability
        for (k, v) in summary.threat_residuals
            @test summary2.threat_residuals[k] ≈ v
        end
        for (k, v) in summary.consequence_risks
            @test summary2.consequence_risks[k] ≈ v
        end
    end

end
