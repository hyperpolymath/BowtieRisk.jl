image:https://img.shields.io/badge/License-PMPL--1.0-blue.svg[License: PMPL-1.0,link="https://github.com/hyperpolymath/palimpsest-license"]

# BowtieRisk.jl




BowtieRisk.jl provides a Julia framework for bowtie risk modeling with an
event-chain view, escalation factors, and basic dependency handling. It is
designed to support structured hazard analysis and the assignment of
probabilities similar to tools like RiskyProject.

This is a new project scaffold with a small, explicit core model. It focuses on
clear data structures, transparent assumptions, and simple calculations that can
be extended for domain-specific needs.

## Installation

### From Julia REPL
```julia
using Pkg
Pkg.add("BowtieRisk")
```

### From Git (Development)
```julia
using Pkg
Pkg.add(url="https://github.com/hyperpolymath/BowtieRisk.jl")
```

## Core Concepts

- **Hazard**: the source of potential harm.
- **Threats**: initiating causes that may trigger a top event.
- **Top Event**: the moment control is lost (center of the bowtie).
- **Consequences**: outcomes following the top event.
- **Barriers**: preventive (left side) or mitigative (right side) controls.
- **Escalation factors**: conditions that reduce barrier effectiveness.
- **Dependencies**: shared-cause failures across barrier groups.
- **Simulation**: Monte Carlo evaluation with barrier distributions.
- **Reporting**: Markdown and CSV outputs for sensitivity data.
- **Templates**: built-in starter models for common scenarios.
- **Schema**: JSON schema for UI integrations.
- **Event Chain**: ordered events with probabilities and barriers.

## Probability Model (Baseline)

This package assumes independent threats and independent barriers by default.
You can switch to a dependency-aware model for shared-cause failures. Under the
independent assumptions:

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
    Barrier(:ReliefValve, 0.7, :preventive, "Relieves excess pressure", 0.1, :none),
    Barrier(:Inspection, 0.5, :preventive, "Detects corrosion", 0.0, :none),
]

consequences = [
    Consequence(:Release, 0.6, "Release to atmosphere"),
    Consequence(:Injury, 0.8, "Personnel injury"),
]

mitigative = [
    Barrier(:GasDetection, 0.6, :mitigative, "Detects release", 0.0, :shared_power),
    Barrier(:Evacuation, 0.5, :mitigative, "Evacuate area", 0.0, :shared_power),
]

model = BowtieModel(
    hazard,
    TopEvent(:ContainmentLost, "Containment is lost"),
    [ThreatPath(threats[1], [preventive[1]], EscalationFactor[]),
     ThreatPath(threats[2], [preventive[2]], EscalationFactor[])],
    [ConsequencePath(consequences[1], [mitigative[1]], EscalationFactor[]),
     ConsequencePath(consequences[2], [mitigative[1], mitigative[2]], EscalationFactor[])],
    ProbabilityModel(:independent),
)

summary = evaluate(model)
println(summary.top_event_probability)
```

## Diagramming Support

BowtieRisk.jl includes helpers that export Mermaid or GraphViz diagram specs.
These are design aids for arranging bowtie diagrams.

```julia
spec = to_mermaid(model)
println(spec)
```

```julia
dot = to_graphviz(model)
println(dot)
```

```julia
write_model_json("bowtie.json", model)
```

```julia
dist = Dict(
    :ReliefValve => BarrierDistribution(:beta, (2.0, 5.0, 0.0)),
    :GasDetection => BarrierDistribution(:triangular, (0.2, 0.5, 0.9)),
)

sim = simulate(model; samples=500, barrier_dists=dist)
tornado = sensitivity_tornado(model; delta=0.1)

write_report_markdown("report.md", model; tornado_data=tornado)
write_tornado_csv("tornado.csv", tornado)
```

```julia
model = template_model(:process_safety)
write_schema_json("bowtie.schema.json")
```

## Development

```bash
julia --project=. -e 'using Pkg; Pkg.instantiate()'
julia --project=. -e 'using Pkg; Pkg.test()'
```

## API Snapshot

```julia
Hazard, Threat, TopEvent, Consequence, Barrier, EscalationFactor
ProbabilityModel, ThreatPath, ConsequencePath, BowtieModel
Event, EventChain, chain_probability
BarrierDistribution, SimulationResult
evaluate, simulate, sensitivity_tornado
to_mermaid, to_graphviz
write_model_json, read_model_json
report_markdown, write_report_markdown, write_tornado_csv
```
