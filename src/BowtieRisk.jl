module BowtieRisk

using JSON3
using Distributions

export Hazard, Threat, TopEvent, Consequence, Barrier, EscalationFactor
export ProbabilityModel, ThreatPath, ConsequencePath, BowtieModel
export BarrierDistribution, SimulationResult
export Event, EventChain, chain_probability
export evaluate, to_mermaid, to_graphviz
export simulate, sensitivity_tornado
export report_markdown, write_report_markdown, write_tornado_csv
export write_model_json, read_model_json

"""
Represents a hazard (source of potential harm).
"""
struct Hazard
    name::Symbol
    description::String
end

"""
Represents a threat (initiating cause) with a baseline probability.
"""
struct Threat
    name::Symbol
    probability::Float64
    description::String
end

"""
Represents the central top event of the bowtie.
"""
struct TopEvent
    name::Symbol
    description::String
end

"""
Represents a consequence with a severity factor (0..1 by convention).
"""
struct Consequence
    name::Symbol
    severity::Float64
    description::String
end

"""
Represents a barrier with effectiveness (0..1), degradation (0..1), and kind.
Dependency symbols model shared-cause barrier failures.
"""
struct Barrier
    name::Symbol
    effectiveness::Float64
    kind::Symbol
    description::String
    degradation::Float64
    dependency::Symbol
end

"""
Represents an escalation factor that reduces barrier effectiveness.
"""
struct EscalationFactor
    name::Symbol
    multiplier::Float64
    description::String
end

"""
Probability model controls dependency handling.
"""
struct ProbabilityModel
    mode::Symbol
end

"""
A threat path leading into the top event.
"""
struct ThreatPath
    threat::Threat
    barriers::Vector{Barrier}
    escalation_factors::Vector{EscalationFactor}
end

"""
A consequence path following the top event.
"""
struct ConsequencePath
    consequence::Consequence
    barriers::Vector{Barrier}
    escalation_factors::Vector{EscalationFactor}
end

"""
Full bowtie model.
"""
struct BowtieModel
    hazard::Hazard
    top_event::TopEvent
    threat_paths::Vector{ThreatPath}
    consequence_paths::Vector{ConsequencePath}
    probability_model::ProbabilityModel
end

"""
Event used in an event chain.
"""
struct Event
    name::Symbol
    probability::Float64
    description::String
end

"""
Ordered event chain with optional barriers and escalation factors.
"""
struct EventChain
    events::Vector{Event}
    barriers::Vector{Barrier}
    escalation_factors::Vector{EscalationFactor}
end

"""
Barrier effectiveness distribution.
Kinds: :fixed, :beta, :triangular.
"""
struct BarrierDistribution
    kind::Symbol
    params::NTuple{3, Float64}
end

"""
Monte Carlo simulation result.
"""
struct SimulationResult
    top_event_mean::Float64
    consequence_means::Dict{Symbol, Float64}
    samples::Vector{Float64}
end

"""
Compute chain probability with barrier reduction (independent assumptions).
"""
function chain_probability(chain::EventChain)
    base = prod((e.probability for e in chain.events); init=1.0)
    reduction = _combined_barrier_reduction(chain.barriers, chain.escalation_factors, ProbabilityModel(:independent))
    base * reduction
end

function _effective_barrier(barrier::Barrier, factors::Vector{EscalationFactor})
    base = clamp(barrier.effectiveness, 0.0, 1.0)
    degraded = base * (1.0 - clamp(barrier.degradation, 0.0, 1.0))
    factor_reduction = prod((1.0 - clamp(f.multiplier, 0.0, 1.0) for f in factors); init=1.0)
    clamp(degraded * factor_reduction, 0.0, 1.0)
end

function _sample_distribution(dist::BarrierDistribution)
    if dist.kind == :fixed
        return clamp(dist.params[1], 0.0, 1.0)
    elseif dist.kind == :beta
        a, b = dist.params[1], dist.params[2]
        return clamp(rand(Beta(a, b)), 0.0, 1.0)
    elseif dist.kind == :triangular
        low, mode, high = dist.params
        u = rand()
        c = (mode - low) / (high - low)
        if u < c
            return low + sqrt(u * (high - low) * (mode - low))
        else
            return high - sqrt((1.0 - u) * (high - low) * (high - mode))
        end
    else
        error("unknown distribution kind: $(dist.kind)")
    end
end

function _apply_distributions(model::BowtieModel, dists::Dict{Symbol, BarrierDistribution})
    function sample_barrier(b::Barrier)
        if haskey(dists, b.name)
            dist = dists[b.name]
            sampled = _sample_distribution(dist)
            return Barrier(b.name, sampled, b.kind, b.description, b.degradation, b.dependency)
        end
        b
    end

    threats = ThreatPath[]
    for p in model.threat_paths
        push!(threats, ThreatPath(p.threat, [sample_barrier(b) for b in p.barriers], p.escalation_factors))
    end

    cons = ConsequencePath[]
    for p in model.consequence_paths
        push!(cons, ConsequencePath(p.consequence, [sample_barrier(b) for b in p.barriers], p.escalation_factors))
    end

    BowtieModel(model.hazard, model.top_event, threats, cons, model.probability_model)
end

function _combined_barrier_reduction(barriers::Vector{Barrier}, factors::Vector{EscalationFactor}, model::ProbabilityModel)
    if isempty(barriers)
        return 1.0
    end

    effective = [_effective_barrier(b, factors) for b in barriers]

    if model.mode == :independent
        return prod((1.0 - e for e in effective); init=1.0)
    elseif model.mode == :dependent
        groups = Dict{Symbol, Vector{Float64}}()
        for (i, b) in enumerate(barriers)
            dep = b.dependency == :none ? Symbol("barrier_$i") : b.dependency
            push!(get!(groups, dep, Float64[]), effective[i])
        end
        combined = [minimum(vals) for vals in values(groups)]
        return prod((1.0 - e for e in combined); init=1.0)
    else
        error("unknown probability model mode: $(model.mode)")
    end
end

function _residual_probability(base::Float64, barriers::Vector{Barrier}, factors::Vector{EscalationFactor}, model::ProbabilityModel)
    reduction = _combined_barrier_reduction(barriers, factors, model)
    base * reduction
end

"""
Evaluate a bowtie model and return a summary struct.
"""
struct BowtieSummary
    top_event_probability::Float64
    threat_residuals::Dict{Symbol, Float64}
    consequence_probabilities::Dict{Symbol, Float64}
    consequence_risks::Dict{Symbol, Float64}
end

"""
Compute residual probabilities, top event probability, and consequence risk.
"""
function evaluate(model::BowtieModel)
    threat_residuals = Dict{Symbol, Float64}()
    residual_values = Float64[]

    for path in model.threat_paths
        base = clamp(path.threat.probability, 0.0, 1.0)
        residual = _residual_probability(base, path.barriers, path.escalation_factors, model.probability_model)
        threat_residuals[path.threat.name] = residual
        push!(residual_values, residual)
    end

    top_event_probability = isempty(residual_values) ? 0.0 : 1.0 - prod(1.0 .- residual_values)

    consequence_probabilities = Dict{Symbol, Float64}()
    consequence_risks = Dict{Symbol, Float64}()

    for path in model.consequence_paths
        residual = _residual_probability(top_event_probability, path.barriers, path.escalation_factors, model.probability_model)
        consequence_probabilities[path.consequence.name] = residual
        severity = clamp(path.consequence.severity, 0.0, 1.0)
        consequence_risks[path.consequence.name] = residual * severity
    end

    BowtieSummary(top_event_probability, threat_residuals, consequence_probabilities, consequence_risks)
end

"""
Run a Monte Carlo simulation with barrier effectiveness distributions.
"""
function simulate(model::BowtieModel; samples::Int=1000, barrier_dists::Dict{Symbol, BarrierDistribution}=Dict())
    top_vals = Float64[]
    cons_vals = Dict{Symbol, Vector{Float64}}()
    for path in model.consequence_paths
        cons_vals[path.consequence.name] = Float64[]
    end

    for _ in 1:samples
        sampled = _apply_distributions(model, barrier_dists)
        summary = evaluate(sampled)
        push!(top_vals, summary.top_event_probability)
        for (k, v) in summary.consequence_probabilities
            push!(cons_vals[k], v)
        end
    end

    cons_means = Dict{Symbol, Float64}()
    for (k, vals) in cons_vals
        cons_means[k] = isempty(vals) ? 0.0 : sum(vals) / length(vals)
    end

    SimulationResult(sum(top_vals) / length(top_vals), cons_means, top_vals)
end

"""
Sensitivity data for tornado charts (low/high values per barrier).
"""
function sensitivity_tornado(model::BowtieModel; delta::Float64=0.1)
    base = evaluate(model).top_event_probability
    results = Vector{Tuple{Symbol, Float64, Float64}}()

    for (pidx, path) in enumerate(model.threat_paths)
        for (bidx, barrier) in enumerate(path.barriers)
            lower = clamp(barrier.effectiveness - delta, 0.0, 1.0)
            upper = clamp(barrier.effectiveness + delta, 0.0, 1.0)

            low_barrier = Barrier(barrier.name, lower, barrier.kind, barrier.description, barrier.degradation, barrier.dependency)
            high_barrier = Barrier(barrier.name, upper, barrier.kind, barrier.description, barrier.degradation, barrier.dependency)

            low_paths = deepcopy(model.threat_paths)
            high_paths = deepcopy(model.threat_paths)
            low_paths[pidx].barriers[bidx] = low_barrier
            high_paths[pidx].barriers[bidx] = high_barrier

            low_model = BowtieModel(model.hazard, model.top_event, low_paths, model.consequence_paths, model.probability_model)
            high_model = BowtieModel(model.hazard, model.top_event, high_paths, model.consequence_paths, model.probability_model)

            push!(results, (barrier.name, evaluate(low_model).top_event_probability, evaluate(high_model).top_event_probability))
        end
    end

    sort!(results, by=x -> abs(x[2] - x[3]), rev=true)
    results
end

"""
Markdown report for a model and optional tornado data.
"""
function report_markdown(model::BowtieModel; tornado_data::Vector{Tuple{Symbol, Float64, Float64}}=Tuple{Symbol, Float64, Float64}[])
    summary = evaluate(model)
    lines = String[]
    push!(lines, "# Bowtie Risk Report")
    push!(lines, "- Hazard: $(model.hazard.name)")
    push!(lines, "- Top event: $(model.top_event.name)")
    push!(lines, "- Top event probability: $(round(summary.top_event_probability, digits=4))")
    push!(lines, "")
    push!(lines, "## Consequences")
    for (k, v) in summary.consequence_probabilities
        push!(lines, "- $(k): $(round(v, digits=4))")
    end

    if !isempty(tornado_data)
        push!(lines, "")
        push!(lines, "## Sensitivity (Tornado)")
        for (name, low, high) in tornado_data
            push!(lines, "- $(name): low=$(round(low, digits=4)) high=$(round(high, digits=4))")
        end
    end
    join(lines, "\n")
end

"""
Write Markdown report to disk.
"""
function write_report_markdown(path::AbstractString, model::BowtieModel; tornado_data::Vector{Tuple{Symbol, Float64, Float64}}=Tuple{Symbol, Float64, Float64}[])
    open(path, "w") do io
        write(io, report_markdown(model; tornado_data=tornado_data))
    end
    nothing
end

"""
Write tornado data to CSV.\n"""
function write_tornado_csv(path::AbstractString, data::Vector{Tuple{Symbol, Float64, Float64}})
    lines = ["barrier,low,high"]
    for (name, low, high) in data
        push!(lines, "$(name),$(low),$(high)")
    end
    open(path, "w") do io
        write(io, join(lines, "\n"))
    end
    nothing
end

"""
Return a Mermaid diagram for a bowtie model.
"""
function to_mermaid(model::BowtieModel)
    lines = String[]
    push!(lines, "flowchart LR")

    hazard_id = "hazard" * string(model.hazard.name)
    top_id = "top" * string(model.top_event.name)

    push!(lines, "  $hazard_id[\"$(model.hazard.name)\"]")
    push!(lines, "  $top_id((\"$(model.top_event.name)\"))")

    for (i, path) in enumerate(model.threat_paths)
        threat_id = "threat$(i)"
        push!(lines, "  $threat_id[\"$(path.threat.name)\"]")
        push!(lines, "  $threat_id --> $top_id")
        for (j, barrier) in enumerate(path.barriers)
            barrier_id = "pb$(i)_$(j)"
            push!(lines, "  $threat_id --- $barrier_id[\"$(barrier.name)\"]")
        end
        for (j, factor) in enumerate(path.escalation_factors)
            factor_id = "pe$(i)_$(j)"
            push!(lines, "  $threat_id -.-> $factor_id[\"$(factor.name)\"]")
        end
    end

    for (i, path) in enumerate(model.consequence_paths)
        cons_id = "cons$(i)"
        push!(lines, "  $top_id --> $cons_id[\"$(path.consequence.name)\"]")
        for (j, barrier) in enumerate(path.barriers)
            barrier_id = "mb$(i)_$(j)"
            push!(lines, "  $cons_id --- $barrier_id[\"$(barrier.name)\"]")
        end
        for (j, factor) in enumerate(path.escalation_factors)
            factor_id = "me$(i)_$(j)"
            push!(lines, "  $cons_id -.-> $factor_id[\"$(factor.name)\"]")
        end
    end

    push!(lines, "  $hazard_id --> $top_id")
    join(lines, "\n")
end

"""
Return a GraphViz DOT diagram for a bowtie model.
"""
function to_graphviz(model::BowtieModel)
    lines = String[]
    push!(lines, "digraph Bowtie {")
    push!(lines, "  rankdir=LR;")

    hazard_id = "hazard" * string(model.hazard.name)
    top_id = "top" * string(model.top_event.name)

    push!(lines, "  $hazard_id [shape=box,label=\"$(model.hazard.name)\"];\n")
    push!(lines, "  $top_id [shape=doublecircle,label=\"$(model.top_event.name)\"];\n")

    for (i, path) in enumerate(model.threat_paths)
        threat_id = "threat$(i)"
        push!(lines, "  $threat_id [shape=box,label=\"$(path.threat.name)\"];\n")
        push!(lines, "  $threat_id -> $top_id;\n")
        for (j, barrier) in enumerate(path.barriers)
            barrier_id = "pb$(i)_$(j)"
            push!(lines, "  $barrier_id [shape=box,label=\"$(barrier.name)\"];\n")
            push!(lines, "  $threat_id -> $barrier_id [style=dashed];\n")
        end
    end

    for (i, path) in enumerate(model.consequence_paths)
        cons_id = "cons$(i)"
        push!(lines, "  $cons_id [shape=box,label=\"$(path.consequence.name)\"];\n")
        push!(lines, "  $top_id -> $cons_id;\n")
        for (j, barrier) in enumerate(path.barriers)
            barrier_id = "mb$(i)_$(j)"
            push!(lines, "  $barrier_id [shape=box,label=\"$(barrier.name)\"];\n")
            push!(lines, "  $cons_id -> $barrier_id [style=dashed];\n")
        end
    end

    push!(lines, "  $hazard_id -> $top_id;\n")
    push!(lines, "}")
    join(lines, "")
end

"""
Write a bowtie model to JSON.
"""
function write_model_json(path::AbstractString, model::BowtieModel)
    obj = Dict{String, Any}()
    obj["hazard"] = Dict("name" => String(model.hazard.name), "description" => model.hazard.description)
    obj["top_event"] = Dict("name" => String(model.top_event.name), "description" => model.top_event.description)
    obj["probability_model"] = Dict("mode" => String(model.probability_model.mode))

    obj["threat_paths"] = [
        Dict(
            "threat" => Dict("name" => String(p.threat.name), "probability" => p.threat.probability, "description" => p.threat.description),
            "barriers" => [
                Dict(
                    "name" => String(b.name),
                    "effectiveness" => b.effectiveness,
                    "kind" => String(b.kind),
                    "description" => b.description,
                    "degradation" => b.degradation,
                    "dependency" => String(b.dependency),
                ) for b in p.barriers
            ],
            "escalation_factors" => [
                Dict("name" => String(f.name), "multiplier" => f.multiplier, "description" => f.description) for f in p.escalation_factors
            ],
        ) for p in model.threat_paths
    ]

    obj["consequence_paths"] = [
        Dict(
            "consequence" => Dict("name" => String(p.consequence.name), "severity" => p.consequence.severity, "description" => p.consequence.description),
            "barriers" => [
                Dict(
                    "name" => String(b.name),
                    "effectiveness" => b.effectiveness,
                    "kind" => String(b.kind),
                    "description" => b.description,
                    "degradation" => b.degradation,
                    "dependency" => String(b.dependency),
                ) for b in p.barriers
            ],
            "escalation_factors" => [
                Dict("name" => String(f.name), "multiplier" => f.multiplier, "description" => f.description) for f in p.escalation_factors
            ],
        ) for p in model.consequence_paths
    ]

    open(path, "w") do io
        JSON3.write(io, obj)
    end
    nothing
end

"""
Read a bowtie model from JSON produced by write_model_json.
"""
function read_model_json(path::AbstractString)
    obj = JSON3.read(read(path, String))
    hazard = Hazard(Symbol(String(obj["hazard"]["name"])), String(obj["hazard"]["description"]))
    top_event = TopEvent(Symbol(String(obj["top_event"]["name"])), String(obj["top_event"]["description"]))
    model = ProbabilityModel(Symbol(String(obj["probability_model"]["mode"])))

    threat_paths = ThreatPath[]
    for p in obj["threat_paths"]
        threat = Threat(Symbol(String(p["threat"]["name"])), Float64(p["threat"]["probability"]), String(p["threat"]["description"]))
        barriers = Barrier[]
        for b in p["barriers"]
            push!(barriers, Barrier(
                Symbol(String(b["name"])),
                Float64(b["effectiveness"]),
                Symbol(String(b["kind"])),
                String(b["description"]),
                Float64(b["degradation"]),
                Symbol(String(b["dependency"])),
            ))
        end
        factors = EscalationFactor[]
        for f in p["escalation_factors"]
            push!(factors, EscalationFactor(Symbol(String(f["name"])), Float64(f["multiplier"]), String(f["description"])))
        end
        push!(threat_paths, ThreatPath(threat, barriers, factors))
    end

    consequence_paths = ConsequencePath[]
    for p in obj["consequence_paths"]
        consequence = Consequence(Symbol(String(p["consequence"]["name"])), Float64(p["consequence"]["severity"]), String(p["consequence"]["description"]))
        barriers = Barrier[]
        for b in p["barriers"]
            push!(barriers, Barrier(
                Symbol(String(b["name"])),
                Float64(b["effectiveness"]),
                Symbol(String(b["kind"])),
                String(b["description"]),
                Float64(b["degradation"]),
                Symbol(String(b["dependency"])),
            ))
        end
        factors = EscalationFactor[]
        for f in p["escalation_factors"]
            push!(factors, EscalationFactor(Symbol(String(f["name"])), Float64(f["multiplier"]), String(f["description"])))
        end
        push!(consequence_paths, ConsequencePath(consequence, barriers, factors))
    end

    BowtieModel(hazard, top_event, threat_paths, consequence_paths, model)
end

end # module
