# SPDX-License-Identifier: PMPL-1.0-or-later
# Basic BowtieRisk.jl Example
# Demonstrates core features: model construction, evaluation, simulation, sensitivity, exports

using BowtieRisk
using Distributions

println("=" ^ 60)
println("BowtieRisk.jl Basic Example")
println("=" ^ 60)

# ============================================================================
# Option 1: Use a template model (process safety)
# ============================================================================
println("\n## Using Process Safety Template")
process_safety = template_model(:process_safety)

# Evaluate the model (deterministic)
summary = evaluate(process_safety)
println("\n### Evaluation Results")
println("Top Event Probability: $(round(summary.top_event_probability, digits=6))")
println("Threat Residuals: $(length(summary.threat_residuals)) threats")
for (name, residual) in summary.threat_residuals
    println("  $name residual: $(round(residual, digits=6))")
end
println("Consequence Probabilities: $(length(summary.consequence_probabilities)) consequences")
for (name, prob) in summary.consequence_probabilities
    println("  $name probability: $(round(prob, digits=6))")
end

# Monte Carlo simulation with uncertainty
println("\n### Monte Carlo Simulation (1000 iterations)")
barrier_dists = Dict{Symbol, BarrierDistribution}(
    :PressureRelief => BarrierDistribution(:beta, (8.0, 2.0, 0.0)),
    :EmergencyShutdown => BarrierDistribution(:beta, (9.0, 1.0, 0.0)),
    :GasDetection => BarrierDistribution(:triangular, (0.7, 0.9, 0.95))
)
sim_result = simulate(process_safety; samples=1000, barrier_dists=barrier_dists)
println("Mean Top Event Probability: $(round(sim_result.top_event_mean, digits=6))")
println("Samples collected: $(length(sim_result.samples))")
println("Consequence means: $(length(sim_result.consequence_means)) consequences")
for (name, mean_val) in sim_result.consequence_means
    println("  $name mean: $(round(mean_val, digits=6))")
end

# Tornado chart sensitivity analysis
println("\n### Tornado Chart Sensitivity (±10%)")
tornado = sensitivity_tornado(process_safety; delta=0.1)
println("Identified $(length(tornado)) sensitive barriers:")
for (name, low, high) in tornado[1:min(5, length(tornado))]
    range_val = high - low
    println("  $name: range = $(round(range_val, digits=6))")
end

# Write tornado data to CSV
mktemp() do path, io
    close(io)  # Close the file handle, we'll write to path
    write_tornado_csv(path, tornado)
    println("\nTornado CSV written to temporary file: $path")
    println("First few lines:")
    lines = readlines(path)
    for line in lines[1:min(5, length(lines))]
        println("  ", line)
    end
end

# Generate markdown report
println("\n### Markdown Report")
report = report_markdown(process_safety; tornado_data=tornado)
println("Report length: $(length(report)) characters")
println("First 200 characters:")
println(first(report, 200))

# Write markdown report to temp file
mktemp() do path, io
    close(io)
    write_report_markdown(path, process_safety; tornado_data=tornado)
    println("\nMarkdown report written to: $path")
end

# Export diagrams
println("\n### Diagram Exports")
mermaid_diagram = to_mermaid(process_safety)
println("Mermaid diagram length: $(length(mermaid_diagram)) characters")
println("First 150 characters:")
println(first(mermaid_diagram, 150))

graphviz_diagram = to_graphviz(process_safety)
println("\nGraphViz diagram length: $(length(graphviz_diagram)) characters")
println("First 150 characters:")
println(first(graphviz_diagram, 150))

# JSON round-trip (write and read back)
println("\n### JSON Round-Trip")
mktemp() do json_path, io
    close(io)
    write_model_json(json_path, process_safety)
    println("Model written to JSON: $json_path")

    reloaded_model = read_model_json(json_path)
    println("Model reloaded from JSON")
    println("Hazard name match: $(reloaded_model.hazard.name == process_safety.hazard.name)")
    println("Top event match: $(reloaded_model.top_event.name == process_safety.top_event.name)")
    println("Threat paths count: $(length(reloaded_model.threat_paths))")
    println("Consequence paths count: $(length(reloaded_model.consequence_paths))")
end

# ============================================================================
# Option 2: Construct a model manually
# ============================================================================
println("\n" * "=" ^ 60)
println("## Manual Model Construction")
println("=" ^ 60)

# Define hazard and top event
hazard = Hazard(:CybersecurityAttack, "Malicious actor targeting system")
top_event = TopEvent(:DataBreach, "Unauthorized access to sensitive data")

# Define threats
threat1 = Threat(:PhishingEmail, 0.20, "Social engineering via email")
threat2 = Threat(:SQLInjection, 0.10, "Code injection vulnerability")

# Define preventive barriers (threat-side)
barrier1 = Barrier(:EmailFiltering, 0.80, :preventive, "Spam/phishing detection", 0.05, :InternetGateway)
barrier2 = Barrier(:SecurityTraining, 0.70, :preventive, "User awareness program", 0.10, :HRPolicy)
barrier3 = Barrier(:InputValidation, 0.90, :preventive, "Parameterized queries", 0.02, :ApplicationLayer)

# Define threat paths
path1 = ThreatPath(threat1, [barrier1, barrier2], EscalationFactor[])
path2 = ThreatPath(threat2, [barrier3], EscalationFactor[])

# Define consequences
consequence1 = Consequence(:CustomerDataExposure, 0.70, "PII leak - financial and reputation damage")
consequence2 = Consequence(:SystemDowntime, 0.30, "Service unavailable - revenue loss")

# Define mitigative barriers (consequence-side)
barrier4 = Barrier(:EncryptionAtRest, 0.85, :mitigative, "AES-256 encryption", 0.01, :StorageLayer)
barrier5 = Barrier(:IncidentResponse, 0.75, :mitigative, "24/7 SOC monitoring", 0.05, :SecurityTeam)

# Define consequence paths
cons_path1 = ConsequencePath(consequence1, [barrier4, barrier5], EscalationFactor[])
cons_path2 = ConsequencePath(consequence2, [barrier5], EscalationFactor[])

# Create model
probability_model = ProbabilityModel(:independent)
manual_model = BowtieModel(hazard, top_event, [path1, path2], [cons_path1, cons_path2], probability_model)

# Evaluate manual model
manual_summary = evaluate(manual_model)
println("\n### Manual Model Evaluation")
println("Top Event Probability: $(round(manual_summary.top_event_probability, digits=6))")
println("Expected Consequence Risks: $(length(manual_summary.consequence_risks))")
for (name, risk) in manual_summary.consequence_risks
    println("  $name risk: \$$(round(risk, digits=0))")
end

# ============================================================================
# List all available templates
# ============================================================================
println("\n" * "=" ^ 60)
println("## Available Templates")
println("=" ^ 60)
templates = list_templates()
println("Available templates: $templates")

println("\n" * "=" ^ 60)
println("Example Complete!")
println("=" ^ 60)
