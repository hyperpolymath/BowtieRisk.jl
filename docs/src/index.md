# BowtieRisk.jl

Documentation for BowtieRisk.jl

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/hyperpolymath/BowtieRisk.jl")
```

## Quick Start

```julia
using BowtieRisk

# Use a template model
model = template_model(:process_safety)

# Evaluate the model
summary = evaluate(model)
println("Top Event Probability: ", summary.top_event_probability)

# Run Monte Carlo simulation
using Distributions
barrier_dists = Dict{Symbol, BarrierDistribution}(
    :ReliefValve => BarrierDistribution(:beta, (8.0, 2.0, 0.0))
)
sim = simulate(model; samples=1000, barrier_dists=barrier_dists)
println("Mean: ", sim.top_event_mean)

# Export to Mermaid diagram
diagram = to_mermaid(model)
println(diagram)
```

See `examples/basic_bowtie.jl` for a comprehensive example.

## API Reference

See [API](api.md) for complete reference.
