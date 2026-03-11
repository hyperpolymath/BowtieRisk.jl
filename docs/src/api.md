# API Reference

## Core Data Structures

```@docs
Hazard
Threat
TopEvent
Consequence
Barrier
EscalationFactor
```

## Model Components

```@docs
ProbabilityModel
ThreatPath
ConsequencePath
BowtieModel
```

## Simulation

```@docs
BarrierDistribution
SimulationResult
simulate
```

## Evaluation

```@docs
BowtieSummary
evaluate
sensitivity_tornado
```

## Event Chains

```@docs
Event
EventChain
chain_probability
```

## Visualization

```@docs
to_mermaid
to_graphviz
```

## Reports

```@docs
report_markdown
write_report_markdown
write_tornado_csv
```

## Serialization

```@docs
write_model_json
read_model_json
write_schema_json
model_schema
```

## Templates

```@docs
list_templates
template_model
```

## Data Import

```@docs
load_simple_csv
```
