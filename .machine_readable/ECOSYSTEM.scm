;; SPDX-License-Identifier: PMPL-1.0-or-later
;; ECOSYSTEM.scm - Ecosystem position for BowtieRisk.jl

(ecosystem
  (version "1.0.0")
  (name "BowtieRisk.jl")
  (type "julia-package")
  (purpose "Formal bowtie risk modeling framework with Monte Carlo simulation and sensitivity analysis")

  (position-in-ecosystem
    "Standalone risk analysis library for Julia. Provides domain-specific modeling for process safety, cybersecurity, and operational risks. Focuses on bowtie methodology (threat → top event → consequence with barriers) rather than general fault tree or event tree analysis.")

  (related-projects
    (("Distributions.jl" . "dependency")
     (description . "Provides probability distributions (Beta, Triangular) for Monte Carlo simulation")
     (relationship . "upstream-dependency")
     (url . "https://github.com/JuliaStats/Distributions.jl"))

    (("JSON3.jl" . "dependency")
     (description . "High-performance JSON serialization for model import/export")
     (relationship . "upstream-dependency")
     (url . "https://github.com/quinnj/JSON3.jl"))

    (("Documenter.jl" . "dev-dependency")
     (description . "Julia documentation generator")
     (relationship . "dev-tooling")
     (url . "https://github.com/JuliaDocs/Documenter.jl"))

    (("FaultTreeAnalysis.jl" . "sibling-alternative")
     (description . "Fault tree analysis library")
     (relationship . "complementary")
     (url . "https://github.com/Example/FaultTreeAnalysis.jl")
     (notes . "Hypothetical package - bowties complement fault trees by adding consequence-side barriers"))

    (("RiskTools.jl" . "potential-consumer")
     (description . "General risk assessment utilities")
     (relationship . "potential-downstream")
     (notes . "Could integrate BowtieRisk.jl as bowtie engine"))

    (("SafetyAnalysis.jl" . "potential-consumer")
     (description . "Safety analysis framework")
     (relationship . "potential-downstream")
     (notes . "Could use BowtieRisk.jl for bowtie diagrams in safety cases"))

    (("RiskMatrix.jl" . "complementary")
     (description . "Risk matrix visualization")
     (relationship . "sibling-tool")
     (notes . "Could consume BowtieRisk.jl output for likelihood/consequence matrices"))

    (("hyperpolymath/rsr-template-repo" . "template-source")
     (description . "RSR template repository with standard workflows")
     (relationship . "governance-template")
     (url . "https://github.com/hyperpolymath/rsr-template-repo")
     (notes . "Provides .github/workflows, RSR file structure, AI.a2ml protocol")))

  (integration-points
    ((name . "JSON import/export")
     (description . "Models can be serialized to JSON for integration with web UIs or other tools")
     (interfaces . ("write_model_json" "read_model_json")))

    ((name . "Mermaid diagrams")
     (description . "Export to Mermaid flowchart syntax for rendering in Markdown/web")
     (interfaces . ("to_mermaid")))

    ((name . "GraphViz DOT")
     (description . "Export to DOT format for rendering with Graphviz tools")
     (interfaces . ("to_graphviz")))

    ((name . "CSV import")
     (description . "Simple CSV import for threat/consequence definitions")
     (interfaces . ("load_simple_csv")))

    ((name . "Markdown reports")
     (description . "Generate narrative risk reports from models")
     (interfaces . ("report_markdown" "write_report_markdown")))

    ((name . "Monte Carlo simulation")
     (description . "Programmatic interface to uncertainty quantification")
     (interfaces . ("simulate" "BarrierDistribution"))))

  (governance
    (maintainer "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")
    (contribution-model "Pull requests welcome, tests required, follows hyperpolymath RSR standards")
    (roadmap-url "https://github.com/hyperpolymath/BowtieRisk.jl/blob/main/ROADMAP.md")
    (security-policy "https://github.com/hyperpolymath/BowtieRisk.jl/blob/main/SECURITY.md")))
