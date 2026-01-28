;; SPDX-License-Identifier: PMPL-1.0-or-later
;; ECOSYSTEM.scm - Project relationship mapping
;; Media Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0")
  (name "BowtieRisk.jl")
  (type "risk-modeling-library")
  (purpose "Framework for bowtie risk analysis with event chains, escalation factors, and Monte Carlo simulation for structured hazard assessment")

  (position-in-ecosystem
    (role "risk-analysis-component")
    (layer "application-library")
    (description "Provides structured bowtie methodology for risk modeling, integrating with causal analysis and risk quantification tools in the hyperpolymath ecosystem"))

  (related-projects
    ((name . "Causals.jl")
     (relationship . "sibling-standard")
     (description . "Causal analysis framework - BowtieRisk models event causality, Causals provides formal causal inference")
     (integration . "BowtieRisk threat-consequence chains can be validated against causal DAGs from Causals.jl"))
    ((name . "Exnovation.jl")
     (relationship . "sibling-standard")
     (description . "Risk mitigation through strategic removal - complements BowtieRisk's barrier-based prevention")
     (integration . "Exnovation strategies can inform which barriers to remove/simplify in BowtieRisk models"))
    ((name . "RiskyProject")
     (relationship . "inspiration")
     (description . "Commercial risk analysis tool - BowtieRisk provides similar probability modeling in FOSS")
     (integration . "Compatible risk scoring methodology, open alternative"))
    ((name . "Axiom.jl")
     (relationship . "potential-consumer")
     (description . "ML reasoning system - could use BowtieRisk for AI safety hazard analysis")
     (integration . "Model AI system failures as bowtie diagrams, quantify risks of ML decisions"))
    ((name . "HackenbushGames.jl")
     (relationship . "potential-consumer")
     (description . "Game theory framework - risk modeling for strategic decision trees")
     (integration . "Game outcomes as consequences, strategies as barriers in competitive scenarios")))

  (what-this-is
    "A Julia library for bowtie risk modeling with transparent probability calculations"
    "Event-chain view of risk progression from threats through top events to consequences"
    "Barrier effectiveness modeling with escalation factors and degradation"
    "Monte Carlo simulation with configurable distributions (beta, triangular)"
    "Sensitivity analysis via tornado charts for parameter importance"
    "Diagram generation (Mermaid flowcharts, GraphViz DOT) for visual communication"
    "JSON serialization with schema for tool integration"
    "Template library for common risk scenarios (process safety, cybersecurity, financial)"
    "Independent and dependent probability models for shared-cause failures"
    "Transparent, auditable calculations for regulatory and safety-critical contexts")

  (what-this-is-not
    "Not a full-featured commercial risk management platform (like RiskyProject or ARM)"
    "Not focused on financial portfolio risk (VaR, CVaR) - use specialized finance libraries"
    "Not a fault tree analysis (FTA) tool - bowtie is complementary, not a replacement"
    "Not a real-time risk monitoring system - designed for analysis and planning"
    "Not a database or risk register - focuses on modeling and calculation"
    "Not FIPS-certified or safety-certified - research and planning tool"
    "Not designed for cryptographic or information security risk - use threat modeling tools"
    "Not a machine learning risk scorer - uses explicit probability assignments"
    "Not a compliance framework - implements methodologies, not regulatory processes"))
