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
        Barrier(:B1, 0.5, :preventive, "Barrier 1"),
        Barrier(:B2, 0.25, :preventive, "Barrier 2"),
    ]

    consequences = [
        Consequence(:C1, 0.8, "Consequence 1"),
        Consequence(:C2, 0.4, "Consequence 2"),
    ]

    mitigative = [
        Barrier(:M1, 0.5, :mitigative, "Barrier 3"),
    ]

    model = BowtieModel(
        hazard,
        top_event,
        [ThreatPath(threats[1], [preventive[1]]), ThreatPath(threats[2], [preventive[2]])],
        [ConsequencePath(consequences[1], [mitigative[1]]), ConsequencePath(consequences[2], Barrier[])],
    )

    summary = evaluate(model)
    @test summary.top_event_probability > 0.0
    @test haskey(summary.threat_residuals, :T1)
    @test haskey(summary.consequence_probabilities, :C1)
    @test summary.consequence_risks[:C1] >= 0.0

    chain = EventChain([Event(:E1, 0.2, "Event 1"), Event(:E2, 0.5, "Event 2")], [mitigative[1]])
    @test chain_probability(chain) ≈ 0.2 * 0.5 * (1.0 - 0.5)
end
