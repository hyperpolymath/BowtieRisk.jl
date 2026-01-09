# BowtieRisk.jl

BowtieRisk.jl provides a Julia framework for bowtie risk modeling with an
optional event-chain view. It is designed to support structured hazard analysis
and the assignment of probabilities similar to tools like RiskyProject.

This is a new project scaffold with a small, explicit core model. It focuses on
clear data structures, transparent assumptions, and simple calculations that can
be extended for domain-specific needs.

## Core Concepts

- **Hazard**: the source of potential harm.
- **Threats**: initiating causes that may trigger a top event.
- **Top Event**: the moment control is lost (center of the bowtie).
- **Consequences**: outcomes following the top event.
- **Barriers**: preventive (left side) or mitigative (right side) controls.
- **Event Chain**: ordered events with probabilities and barriers.

## Probability Model (Baseline)

This package assumes independent threats and independent barriers unless you
provide a different model. Under those assumptions:

- Threat residual = `p(threat) * Π(1 - barrier_effectiveness)`
- Top event probability = `1 - Π(1 - threat_residual)`
- Consequence probability = `p(top_event) * Π(1 - barrier_effectiveness)`
- Risk score = `probability * severity`

These formulas are intentionally simple and transparent so they can be replaced
with richer methods later.

## Quick Start

```julia
using BowtieRisk

hazard = Hazard(:LossOfContainment, "Loss of containment from vessel")

threats = [
    Threat(:Overpressure, 0.02, "Pressure exceeds design"),
    Threat(:Corrosion, 0.01, "Wall thinning"),
]

preventive = [
    Barrier(:ReliefValve, 0.7, :preventive, "Relieves excess pressure"),
    Barrier(:Inspection, 0.5, :preventive, "Detects corrosion"),
]

consequences = [
    Consequence(:Release, 0.6, "Release to atmosphere"),
    Consequence(:Injury, 0.8, "Personnel injury"),
]

mitigative = [
    Barrier(:GasDetection, 0.6, :mitigative, "Detects release"),
    Barrier(:Evacuation, 0.5, :mitigative, "Evacuate area"),
]

model = BowtieModel(
    hazard,
    TopEvent(:ContainmentLost, "Containment is lost"),
    [ThreatPath(threats[1], [preventive[1]]),
     ThreatPath(threats[2], [preventive[2]])],
    [ConsequencePath(consequences[1], [mitigative[1]]),
     ConsequencePath(consequences[2], [mitigative[1], mitigative[2]])],
)

summary = evaluate(model)
println(summary.top_event_probability)
```

## Diagramming Support

BowtieRisk.jl includes a small helper that exports a Mermaid diagram spec. This
is a design aid for arranging bowtie diagrams, inspired by common guidance for
clear, readable risk diagrams.

```julia
spec = to_mermaid(model)
println(spec)
```

## Development

```bash
julia --project=. -e 'using Pkg; Pkg.instantiate()'
julia --project=. -e 'using Pkg; Pkg.test()'
```
