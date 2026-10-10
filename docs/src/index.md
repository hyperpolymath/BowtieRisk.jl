# BowtieRisk.jl

Documentation for BowtieRisk.jl: bow-tie risk analysis with barrier assessment and Monte Carlo simulation.

## Installation

BowtieRisk depends on AcceleratorGate.jl, which is not in the General registry. Add it first, from the pinned revision:

```julia
using Pkg
Pkg.add(url="https://github.com/hyperpolymath/AcceleratorGate.jl.git",
        rev="680205c9c167d1d9ab0bb5a6034852f3d8e06149")
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

See [API](api.md) for the complete reference.
