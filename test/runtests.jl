# SPDX-License-Identifier: PMPL-1.0-or-later
using Test
using BowtieRisk

@testset "BowtieRisk" begin
    hazard = Hazard(:Hazard, "Test hazard")
    top_event = TopEvent(:Top, "Top event")

    threats = [
        Threat(:T1, 0.2, "Threat 1"),
        Threat(:T2, 0.1, "Threat 2"),
    ]

    preventive = [
        Barrier(:B1, 0.5, :preventive, "Barrier 1", 0.0, :none),
        Barrier(:B2, 0.25, :preventive, "Barrier 2", 0.0, :none),
    ]

    consequences = [
        Consequence(:C1, 0.8, "Consequence 1"),
        Consequence(:C2, 0.4, "Consequence 2"),
    ]

    mitigative = [
        Barrier(:M1, 0.5, :mitigative, "Barrier 3", 0.1, :shared_power),
    ]

    model = BowtieModel(
        hazard,
        top_event,
        [ThreatPath(threats[1], [preventive[1]], EscalationFactor[]), ThreatPath(threats[2], [preventive[2]], EscalationFactor[])],
        [ConsequencePath(consequences[1], [mitigative[1]], EscalationFactor[]), ConsequencePath(consequences[2], Barrier[], EscalationFactor[])],
        ProbabilityModel(:independent),
    )

    summary = evaluate(model)
    @test summary.top_event_probability > 0.0
    @test haskey(summary.threat_residuals, :T1)
    @test haskey(summary.consequence_probabilities, :C1)
    @test summary.consequence_risks[:C1] >= 0.0

    # Edge case: Zero probability threat
    zero_threat = Threat(:T0, 0.0, "Zero threat")
    model_zero_threat = BowtieModel(
        hazard,
        top_event,
        [ThreatPath(zero_threat, Barrier[], EscalationFactor[])],
        [ConsequencePath(consequences[1], Barrier[], EscalationFactor[])],
        ProbabilityModel(:independent),
    )
    summary_zero = evaluate(model_zero_threat)
    @test summary_zero.top_event_probability >= 0.0

    # Edge case: Perfect barrier (100% effective)
    perfect_barrier = Barrier(:BP, 1.0, :preventive, "Perfect", 0.0, :none)
    model_perfect = BowtieModel(
        hazard,
        top_event,
        [ThreatPath(threats[1], [perfect_barrier], EscalationFactor[])],
        [ConsequencePath(consequences[1], Barrier[], EscalationFactor[])],
        ProbabilityModel(:independent),
    )
    summary_perfect = evaluate(model_perfect)
    @test summary_perfect.top_event_probability == 0.0

    # Edge case: No barriers at all
    model_no_barriers = BowtieModel(
        hazard,
        top_event,
        [ThreatPath(threats[1], Barrier[], EscalationFactor[])],
        [ConsequencePath(consequences[1], Barrier[], EscalationFactor[])],
        ProbabilityModel(:independent),
    )
    summary_no_barriers = evaluate(model_no_barriers)
    @test summary_no_barriers.top_event_probability ≈ threats[1].probability

    chain = EventChain([Event(:E1, 0.2, "Event 1"), Event(:E2, 0.5, "Event 2")], [mitigative[1]], EscalationFactor[])
    @test chain_probability(chain) ≈ 0.2 * 0.5 * (1.0 - (0.5 * 0.9))

    dependent = BowtieModel(
        hazard,
        top_event,
        [ThreatPath(threats[1], [preventive[1]], EscalationFactor[])],
        [ConsequencePath(consequences[1], [mitigative[1]], EscalationFactor[])],
        ProbabilityModel(:dependent),
    )
    @test evaluate(dependent).top_event_probability > 0.0

    mermaid = to_mermaid(model)
    dot = to_graphviz(model)
    @test occursin("flowchart", mermaid)
    @test occursin("digraph", dot)

    path = joinpath(@__DIR__, "bowtie.json")
    write_model_json(path, model)
    model2 = read_model_json(path)
    @test model2.top_event.name == :Top
    rm(path, force=true)

    dists = Dict{Symbol, BarrierDistribution}(
        :B1 => BarrierDistribution(:beta, (2.0, 5.0, 0.0)),
        :M1 => BarrierDistribution(:triangular, (0.2, 0.5, 0.9)),
    )
    sim = simulate(model; samples=20, barrier_dists=dists)
    @test sim.top_event_mean >= 0.0
    @test haskey(sim.consequence_means, :C1)

    # Edge case: Monte Carlo with minimal samples
    sim_min = simulate(model; samples=5, barrier_dists=dists)
    @test sim_min.top_event_mean >= 0.0

    # Edge case: Monte Carlo with many samples
    sim_many = simulate(model; samples=100, barrier_dists=dists)
    @test sim_many.top_event_mean >= 0.0
    @test abs(sim_many.top_event_mean - summary.top_event_probability) < 0.5

    # Note: SimulationResult does not currently track standard deviation
    # Future enhancement: add top_event_std field

    # Edge case: Simulation with no distributions (uses nominal values)
    sim_nominal = simulate(model; samples=20, barrier_dists=Dict{Symbol, BarrierDistribution}())
    @test sim_nominal.top_event_mean >= 0.0

    tornado = sensitivity_tornado(model; delta=0.1)
    @test !isempty(tornado)

    # Edge case: Sensitivity with different delta values
    tornado_small = sensitivity_tornado(model; delta=0.05)
    @test !isempty(tornado_small)
    tornado_large = sensitivity_tornado(model; delta=0.2)
    @test !isempty(tornado_large)

    # Test that tornado contains expected barrier names
    barrier_names = [t[1] for t in tornado]  # t[1] is the parameter (Symbol)
    @test :B1 in barrier_names || :T1 in barrier_names

    # Test sensitivity ordering (most impactful first)
    if length(tornado) > 1
        impact1 = abs(tornado[1][2] - tornado[1][3])
        impact_last = abs(tornado[end][2] - tornado[end][3])
        @test impact1 >= impact_last
    end
    report_path = joinpath(@__DIR__, "report.md")
    write_report_markdown(report_path, model; tornado_data=tornado)
    @test isfile(report_path)
    rm(report_path, force=true)

    csv_path = joinpath(@__DIR__, "tornado.csv")
    write_tornado_csv(csv_path, tornado)
    @test isfile(csv_path)
    rm(csv_path, force=true)

    templ = template_model(:process_safety)
    @test templ.top_event.name == :ContainmentLost

    # Test all implemented template types
    for template_type in [:process_safety, :cyber_incident]
        t = template_model(template_type)
        @test t isa BowtieModel
        summary_t = evaluate(t)
        @test summary_t.top_event_probability >= 0.0
    end

    schema_path = joinpath(@__DIR__, "schema.json")
    write_schema_json(schema_path)
    @test isfile(schema_path)
    rm(schema_path, force=true)

    simple_path = joinpath(@__DIR__, "simple.csv")
    open(simple_path, "w") do io
        write(io, "a,b\n1,2\n")
    end
    rows = load_simple_csv(simple_path)
    @test rows[1]["a"] == "1"
    rm(simple_path, force=true)

    # ====================================================================
    # Point-to-point tests (individual function coverage gaps)
    # ====================================================================

    @testset "EscalationFactor application" begin
        # Escalation factors reduce barrier effectiveness, increasing residual probability
        barrier = Barrier(:test, 0.9, :preventive, "test barrier", 0.0, :none)
        ef = EscalationFactor(:training, 0.3, "Bad training")

        # Model WITHOUT escalation factor
        model_no_ef = BowtieModel(
            Hazard(:H, "Hazard"),
            TopEvent(:T, "Top"),
            [ThreatPath(Threat(:X, 0.1, "Threat"), [barrier], EscalationFactor[])],
            [ConsequencePath(Consequence(:C, 0.5, "Cons"), Barrier[], EscalationFactor[])],
            ProbabilityModel(:independent),
        )
        # Model WITH escalation factor
        model_with_ef = BowtieModel(
            Hazard(:H, "Hazard"),
            TopEvent(:T, "Top"),
            [ThreatPath(Threat(:X, 0.1, "Threat"), [barrier], [ef])],
            [ConsequencePath(Consequence(:C, 0.5, "Cons"), Barrier[], EscalationFactor[])],
            ProbabilityModel(:independent),
        )

        s_no = evaluate(model_no_ef)
        s_with = evaluate(model_with_ef)

        # Escalation factor should weaken the barrier, increasing residual probability
        @test s_with.top_event_probability > s_no.top_event_probability
        @test s_with.threat_residuals[:X] > s_no.threat_residuals[:X]

        # Without EF: residual = 0.1 * (1 - 0.9) = 0.01
        @test s_no.threat_residuals[:X] ≈ 0.01
        # With EF: effective = 0.9 * (1 - 0.3) = 0.63, residual = 0.1 * (1 - 0.63) = 0.037
        @test s_with.threat_residuals[:X] ≈ 0.1 * (1.0 - 0.9 * (1.0 - 0.3))
    end

    @testset "Barrier degradation" begin
        # Degradation > 0 reduces effective barrier strength
        barrier_fresh = Barrier(:valve, 0.9, :preventive, "Relief valve", 0.0, :none)
        barrier_degraded = Barrier(:valve, 0.9, :preventive, "Relief valve", 0.3, :none)

        threat = Threat(:leak, 0.1, "Leak")
        cons = ConsequencePath(Consequence(:C, 0.5, "Consequence"), Barrier[], EscalationFactor[])

        model_fresh = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(threat, [barrier_fresh], EscalationFactor[])],
            [cons],
            ProbabilityModel(:independent),
        )
        model_degraded = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(threat, [barrier_degraded], EscalationFactor[])],
            [cons],
            ProbabilityModel(:independent),
        )

        s_fresh = evaluate(model_fresh)
        s_degraded = evaluate(model_degraded)

        # Degraded barrier should yield higher residual probability
        @test s_degraded.top_event_probability > s_fresh.top_event_probability
        # Fresh: residual = 0.1 * (1 - 0.9) = 0.01
        @test s_fresh.threat_residuals[:leak] ≈ 0.01
        # Degraded: effective = 0.9 * (1 - 0.3) = 0.63, residual = 0.1 * (1 - 0.63) = 0.037
        @test s_degraded.threat_residuals[:leak] ≈ 0.1 * (1.0 - 0.9 * 0.7)
    end

    @testset "Dependent probability model - shared cause" begin
        # Barriers with the same dependency group fail together in :dependent mode
        b1 = Barrier(:insp1, 0.8, :preventive, "Inspection A", 0.0, :shared_maintenance)
        b2 = Barrier(:insp2, 0.7, :preventive, "Inspection B", 0.0, :shared_maintenance)
        b3 = Barrier(:alarm, 0.9, :preventive, "Alarm", 0.0, :none)

        threat = Threat(:fault, 0.1, "Equipment fault")
        cons = ConsequencePath(Consequence(:C, 0.5, "Consequence"), Barrier[], EscalationFactor[])

        model_indep = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(threat, [b1, b2, b3], EscalationFactor[])],
            [cons],
            ProbabilityModel(:independent),
        )
        model_dep = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(threat, [b1, b2, b3], EscalationFactor[])],
            [cons],
            ProbabilityModel(:dependent),
        )

        s_indep = evaluate(model_indep)
        s_dep = evaluate(model_dep)

        # In :independent mode: residual = 0.1 * (1-0.8) * (1-0.7) * (1-0.9) = 0.1 * 0.006 = 0.0006
        @test s_indep.threat_residuals[:fault] ≈ 0.1 * 0.2 * 0.3 * 0.1

        # In :dependent mode: shared_maintenance group takes min(0.8, 0.7) = 0.7
        # Then: residual = 0.1 * (1-0.7) * (1-0.9) = 0.1 * 0.3 * 0.1 = 0.003
        @test s_dep.threat_residuals[:fault] ≈ 0.1 * 0.3 * 0.1

        # Dependent mode should yield higher residual (fewer effective barriers)
        @test s_dep.threat_residuals[:fault] > s_indep.threat_residuals[:fault]
    end

    @testset "Error conditions" begin
        # Unknown template should throw
        @test_throws ErrorException template_model(:nonexistent)

        # Unknown probability model mode should throw during evaluate
        bad_model = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(Threat(:X, 0.1, "Threat"), [Barrier(:B, 0.5, :preventive, "B", 0.0, :none)], EscalationFactor[])],
            [ConsequencePath(Consequence(:C, 0.5, "Cons"), Barrier[], EscalationFactor[])],
            ProbabilityModel(:bogus),
        )
        @test_throws ErrorException evaluate(bad_model)

        # Unknown distribution kind should throw during simulation
        bad_dist = Dict(:B => BarrierDistribution(:unknown_dist, (0.5, 0.5, 0.5)))
        simple_model = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(Threat(:X, 0.1, "Threat"), [Barrier(:B, 0.5, :preventive, "B", 0.0, :none)], EscalationFactor[])],
            [ConsequencePath(Consequence(:C, 0.5, "Cons"), Barrier[], EscalationFactor[])],
            ProbabilityModel(:independent),
        )
        @test_throws ErrorException simulate(simple_model; samples=5, barrier_dists=bad_dist)

        # Invalid triangular distribution parameters should throw
        bad_tri_dist = Dict(:B => BarrierDistribution(:triangular, (0.9, 0.1, 0.5)))
        @test_throws ArgumentError simulate(simple_model; samples=5, barrier_dists=bad_tri_dist)
    end

    @testset "CSV edge cases" begin
        dir = mktempdir()

        # Empty CSV (no rows)
        empty_path = joinpath(dir, "empty.csv")
        open(empty_path, "w") do io
            write(io, "")
        end
        @test load_simple_csv(empty_path) == Dict{String, String}[]

        # Header only, no data rows
        header_only = joinpath(dir, "header.csv")
        open(header_only, "w") do io
            write(io, "name,value\n")
        end
        @test load_simple_csv(header_only) == Dict{String, String}[]

        # Rows with fewer columns than header
        short_row = joinpath(dir, "short.csv")
        open(short_row, "w") do io
            write(io, "a,b,c\n1\n")
        end
        rows_short = load_simple_csv(short_row)
        @test length(rows_short) == 1
        @test rows_short[1]["a"] == "1"
        @test rows_short[1]["b"] == ""
        @test rows_short[1]["c"] == ""

        # Blank lines should be skipped
        blanks_path = joinpath(dir, "blanks.csv")
        open(blanks_path, "w") do io
            write(io, "x,y\n1,2\n\n3,4\n")
        end
        rows_blanks = load_simple_csv(blanks_path)
        @test length(rows_blanks) == 2
        @test rows_blanks[1]["x"] == "1"
        @test rows_blanks[2]["x"] == "3"
    end

    @testset "Consequence-side barrier sensitivity" begin
        # Mitigative barriers should reduce consequence risk
        barrier_mit = Barrier(:firewall, 0.8, :mitigative, "Firewall", 0.0, :none)
        threat = Threat(:attack, 0.1, "Attack")
        cons = Consequence(:breach, 0.9, "Data breach")

        model_with_mit = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(threat, Barrier[], EscalationFactor[])],
            [ConsequencePath(cons, [barrier_mit], EscalationFactor[])],
            ProbabilityModel(:independent),
        )
        model_without_mit = BowtieModel(
            Hazard(:H, "Hazard"), TopEvent(:T, "Top"),
            [ThreatPath(threat, Barrier[], EscalationFactor[])],
            [ConsequencePath(cons, Barrier[], EscalationFactor[])],
            ProbabilityModel(:independent),
        )

        s_with = evaluate(model_with_mit)
        s_without = evaluate(model_without_mit)

        # Both have same top event probability (no preventive barriers)
        @test s_with.top_event_probability ≈ s_without.top_event_probability

        # Mitigative barrier should reduce consequence probability and risk
        @test s_with.consequence_probabilities[:breach] < s_without.consequence_probabilities[:breach]
        @test s_with.consequence_risks[:breach] < s_without.consequence_risks[:breach]

        # Without barrier: cons_prob = top_event_prob * 1.0 = 0.1
        @test s_without.consequence_probabilities[:breach] ≈ 0.1
        # With barrier: cons_prob = 0.1 * (1 - 0.8) = 0.02
        @test s_with.consequence_probabilities[:breach] ≈ 0.1 * 0.2
    end

    @testset "Large model stress test" begin
        # 50 barriers across 20 threat paths, 10 consequence paths
        threat_paths = [ThreatPath(
            Threat(Symbol("t$i"), 0.01 * i, "Threat $i"),
            [Barrier(Symbol("b$(i)_$(j)"), 0.5 + 0.05j, :preventive, "B", 0.0, :none) for j in 1:5],
            EscalationFactor[],
        ) for i in 1:10]
        consequence_paths = [ConsequencePath(
            Consequence(Symbol("c$i"), 0.1 * i, "Consequence $i"),
            [Barrier(Symbol("mb$(i)_$(j)"), 0.6 + 0.05j, :mitigative, "MB", 0.0, :none) for j in 1:3],
            EscalationFactor[],
        ) for i in 1:5]

        big_model = BowtieModel(
            Hazard(:BigHazard, "Large scenario"),
            TopEvent(:BigEvent, "Large top event"),
            threat_paths, consequence_paths,
            ProbabilityModel(:independent),
        )

        s = evaluate(big_model)
        @test 0 < s.top_event_probability < 1
        @test length(s.threat_residuals) == 10
        @test length(s.consequence_risks) == 5

        # All residuals should be positive (threats have nonzero probability)
        for (k, v) in s.threat_residuals
            @test v > 0
        end

        # Mermaid and GraphViz should handle large models
        m = to_mermaid(big_model)
        g = to_graphviz(big_model)
        @test occursin("BigHazard", m)
        @test occursin("BigHazard", g)
    end

    # ====================================================================
    # End-to-end workflow test
    # ====================================================================

    @testset "End-to-end: Chemical Plant Fire Scenario" begin
        # 1. DEFINE hazard
        hazard_e2e = Hazard(:ChemicalFire, "Uncontrolled chemical reaction")
        top_event_e2e = TopEvent(:FireIgnition, "Fire initiates and spreads")

        # 2. BUILD threat paths with escalation factors and degradation
        threat_paths_e2e = [
            ThreatPath(
                Threat(:EquipmentFailure, 0.05, "Pump seal failure"),
                [
                    Barrier(:PressureRelief, 0.8, :preventive, "Relief valve", 0.05, :none),
                    Barrier(:Inspection, 0.6, :preventive, "Regular inspection", 0.1, :shared_maint),
                ],
                [EscalationFactor(:TrainingGap, 0.3, "Poor operator training")],
            ),
            ThreatPath(
                Threat(:ExternalIgnition, 0.02, "Hot work ignition"),
                [Barrier(:HotWorkPermit, 0.7, :preventive, "Permit system", 0.0, :shared_maint)],
                EscalationFactor[],
            ),
        ]

        # 3. BUILD consequence paths
        consequence_paths_e2e = [
            ConsequencePath(
                Consequence(:PersonnelExposure, 0.9, "Worker exposure"),
                [
                    Barrier(:Evacuation, 0.8, :mitigative, "Evacuation plan", 0.1, :none),
                    Barrier(:PPE, 0.6, :mitigative, "PPE", 0.2, :shared_training),
                ],
                [EscalationFactor(:Crowding, 0.4, "Exit congestion")],
            ),
            ConsequencePath(
                Consequence(:EnvironmentalDamage, 0.7, "Soil contamination"),
                [Barrier(:Containment, 0.95, :mitigative, "Spill berm", 0.0, :none)],
                EscalationFactor[],
            ),
        ]

        # 4. BUILD model with dependent mode
        model_e2e = BowtieModel(hazard_e2e, top_event_e2e, threat_paths_e2e, consequence_paths_e2e, ProbabilityModel(:dependent))

        # 5. EVALUATE deterministically
        summary_e2e = evaluate(model_e2e)
        @test 0 < summary_e2e.top_event_probability < 1
        @test haskey(summary_e2e.threat_residuals, :EquipmentFailure)
        @test haskey(summary_e2e.threat_residuals, :ExternalIgnition)
        @test haskey(summary_e2e.consequence_risks, :PersonnelExposure)
        @test haskey(summary_e2e.consequence_risks, :EnvironmentalDamage)
        # Barriers should reduce risk below the raw threat probability
        @test summary_e2e.threat_residuals[:EquipmentFailure] < 0.05
        @test summary_e2e.threat_residuals[:ExternalIgnition] < 0.02

        # 6. SIMULATE with distributions
        barrier_dists_e2e = Dict(
            :PressureRelief => BarrierDistribution(:beta, (5.0, 2.0, 0.0)),
            :Inspection => BarrierDistribution(:triangular, (0.3, 0.6, 0.9)),
            :Evacuation => BarrierDistribution(:beta, (3.0, 2.0, 0.0)),
        )
        sim_e2e = simulate(model_e2e; samples=2000, barrier_dists=barrier_dists_e2e)
        @test sim_e2e.top_event_mean > 0
        @test length(sim_e2e.samples) == 2000
        @test abs(sim_e2e.top_event_mean - summary_e2e.top_event_probability) < 0.3

        # 7. SENSITIVITY analysis
        tornado_e2e = sensitivity_tornado(model_e2e; delta=0.15)
        @test length(tornado_e2e) > 0
        # Should be sorted by impact (descending)
        impacts_e2e = [abs(t[3] - t[2]) for t in tornado_e2e]
        @test issorted(impacts_e2e, rev=true)

        # 8. EXPORT all formats
        dir_e2e = mktempdir()
        write_model_json(joinpath(dir_e2e, "model.json"), model_e2e)
        write_report_markdown(joinpath(dir_e2e, "report.md"), model_e2e; tornado_data=tornado_e2e)
        write_tornado_csv(joinpath(dir_e2e, "tornado.csv"), tornado_e2e)
        write_schema_json(joinpath(dir_e2e, "schema.json"))

        @test isfile(joinpath(dir_e2e, "model.json"))
        @test isfile(joinpath(dir_e2e, "report.md"))
        @test isfile(joinpath(dir_e2e, "tornado.csv"))
        @test isfile(joinpath(dir_e2e, "schema.json"))

        # 9. DIAGRAM outputs
        mermaid_e2e = to_mermaid(model_e2e)
        graphviz_e2e = to_graphviz(model_e2e)
        @test contains(mermaid_e2e, "ChemicalFire")
        @test contains(mermaid_e2e, "FireIgnition")
        @test contains(graphviz_e2e, "ChemicalFire")

        # 10. ROUND-TRIP (JSON -> load -> re-evaluate)
        model2_e2e = read_model_json(joinpath(dir_e2e, "model.json"))
        summary2_e2e = evaluate(model2_e2e)
        @test summary2_e2e.top_event_probability ≈ summary_e2e.top_event_probability
        for (k, v) in summary_e2e.threat_residuals
            @test summary2_e2e.threat_residuals[k] ≈ v
        end
        for (k, v) in summary_e2e.consequence_risks
            @test summary2_e2e.consequence_risks[k] ≈ v
        end

        # 11. REPORT content validation
        report_e2e = report_markdown(model_e2e; tornado_data=tornado_e2e)
        @test contains(report_e2e, "ChemicalFire")
        @test contains(report_e2e, "Sensitivity")
    end

    # ====================================================================
    # Performance benchmarks
    # ====================================================================

    @testset "Performance benchmarks" begin
        # Build a large model: 20 threat paths x 5 barriers, 10 consequence paths x 3 barriers
        perf_threats = [ThreatPath(
            Threat(Symbol("t$i"), 0.01 * i, "Threat $i"),
            [Barrier(Symbol("b$(i)_$(j)"), 0.5 + 0.05j, :preventive, "B", 0.0, :none) for j in 1:5],
            EscalationFactor[],
        ) for i in 1:20]
        perf_consequences = [ConsequencePath(
            Consequence(Symbol("c$i"), 0.1 * i, "Consequence $i"),
            [Barrier(Symbol("mb$(i)_$(j)"), 0.6 + 0.05j, :mitigative, "MB", 0.0, :none) for j in 1:3],
            EscalationFactor[],
        ) for i in 1:10]
        big_model_perf = BowtieModel(
            Hazard(:BigHazard, "Large scenario"),
            TopEvent(:BigEvent, "Large top event"),
            perf_threats, perf_consequences,
            ProbabilityModel(:independent),
        )

        # Warm up JIT
        evaluate(big_model_perf)
        simulate(big_model_perf; samples=10, barrier_dists=Dict{Symbol, BarrierDistribution}())
        sensitivity_tornado(big_model_perf)

        # Evaluate should complete quickly
        t_eval = @elapsed evaluate(big_model_perf)
        @test t_eval < 1.0

        # Simulate should complete in reasonable time
        t_sim = @elapsed simulate(big_model_perf; samples=5000, barrier_dists=Dict{Symbol, BarrierDistribution}())
        @test t_sim < 30.0

        # Sensitivity should complete
        t_sens = @elapsed sensitivity_tornado(big_model_perf)
        @test t_sens < 10.0
    end
end
