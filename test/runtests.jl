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
end
