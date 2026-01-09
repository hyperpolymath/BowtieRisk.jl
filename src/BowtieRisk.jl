module BowtieRisk

using JSON3

export Hazard, Threat, TopEvent, Consequence, Barrier, EscalationFactor
export ProbabilityModel, ThreatPath, ConsequencePath, BowtieModel
export Event, EventChain, chain_probability
export evaluate, to_mermaid, to_graphviz
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
