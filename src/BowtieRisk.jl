module BowtieRisk

export Hazard, Threat, TopEvent, Consequence, Barrier
export ThreatPath, ConsequencePath, BowtieModel
export Event, EventChain, chain_probability
export evaluate, to_mermaid

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
Represents a barrier with effectiveness (0..1) and kind (:preventive or :mitigative).
"""
struct Barrier
    name::Symbol
    effectiveness::Float64
    kind::Symbol
    description::String
end

"""
A threat path leading into the top event.
"""
struct ThreatPath
    threat::Threat
    barriers::Vector{Barrier}
end

"""
A consequence path following the top event.
"""
struct ConsequencePath
    consequence::Consequence
    barriers::Vector{Barrier}
end

"""
Full bowtie model.
"""
struct BowtieModel
    hazard::Hazard
    top_event::TopEvent
    threat_paths::Vector{ThreatPath}
    consequence_paths::Vector{ConsequencePath}
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
Ordered event chain with optional barriers.
"""
struct EventChain
    events::Vector{Event}
    barriers::Vector{Barrier}
end

"""
Compute chain probability with barrier reduction (independent assumptions).
"""
function chain_probability(chain::EventChain)
    base = prod((e.probability for e in chain.events); init=1.0)
    reduction = prod((1.0 - clamp(b.effectiveness, 0.0, 1.0) for b in chain.barriers); init=1.0)
    base * reduction
end

function _residual_probability(base::Float64, barriers::Vector{Barrier})
    reduction = prod((1.0 - clamp(b.effectiveness, 0.0, 1.0) for b in barriers); init=1.0)
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
        residual = _residual_probability(base, path.barriers)
        threat_residuals[path.threat.name] = residual
        push!(residual_values, residual)
    end

    top_event_probability = isempty(residual_values) ? 0.0 : 1.0 - prod(1.0 .- residual_values)

    consequence_probabilities = Dict{Symbol, Float64}()
    consequence_risks = Dict{Symbol, Float64}()

    for path in model.consequence_paths
        residual = _residual_probability(top_event_probability, path.barriers)
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
    end

    for (i, path) in enumerate(model.consequence_paths)
        cons_id = "cons$(i)"
        push!(lines, "  $top_id --> $cons_id[\"$(path.consequence.name)\"]")
        for (j, barrier) in enumerate(path.barriers)
            barrier_id = "mb$(i)_$(j)"
            push!(lines, "  $cons_id --- $barrier_id[\"$(barrier.name)\"]")
        end
    end

    push!(lines, "  $hazard_id --> $top_id")
    join(lines, "\n")
end

end # module
