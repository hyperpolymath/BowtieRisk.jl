;; SPDX-License-Identifier: PMPL-1.0-or-later
;; META.scm - BowtieRisk.jl architectural decisions and design rationale
;; Media Type: application/meta+scheme

(define-module (meta bowtierisk)
  #:use-module (ice-9 match)
  #:export (meta get-adr))

(define meta
  '((metadata
      (version . "0.1.0")
      (schema-version . "1.0.0")
      (created . "2026-01-28")
      (updated . "2026-01-28")
      (project . "BowtieRisk.jl")
      (media-type . "application/meta+scheme"))

    (architecture-decisions
      ((adr-001
         (title . "Transparent probability model with explicit assumptions")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Many risk tools use opaque calculations. Safety-critical and regulatory contexts require auditable formulas. Users need to understand and validate risk scores.")
         (decision . "Use simple, explicit probability formulas documented in README. Residual = p(threat) × Π(1 - effectiveness). Top event = 1 - Π(1 - residual). Risk = probability × severity. Make all assumptions visible and replaceable.")
         (consequences . "Positive: Auditable calculations, easy validation, regulatory acceptance. Negative: Less sophisticated than research models, users may need custom implementations for complex scenarios."))
       (adr-002
         (title . "Event chain as first-class concept")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Bowtie diagrams traditionally show threats→top event→consequences. Real scenarios involve sequential events (detection lag, escalation, recovery). Need temporal view.")
         (decision . "Introduce EventChain struct with ordered events, barriers between events, and chain_probability function. Complements bowtie view with temporal progression.")
         (consequences . "Positive: Models multi-stage failures, supports timeline analysis. Negative: Adds complexity beyond standard bowtie, requires user understanding of chain semantics."))
       (adr-003
         (title . "Escalation factors as multipliers on barrier effectiveness")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Barriers degrade under stress (environmental, organizational, resource). Standard bowtie models lack this. Need to model barrier degradation without complex dependencies.")
         (decision . "EscalationFactor struct with multiplier (0..1) applied to barrier effectiveness. Example: high stress × 0.7 reduces barrier. Composable: multiple factors multiply.")
         (consequences . "Positive: Models realistic barrier degradation, simple semantics. Negative: Multiplicative model may not capture all degradation types, requires careful calibration."))
       (adr-004
         (title . "Independent and dependent probability modes")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Barriers often fail independently (inspection, relief valve) but can share causes (power loss, common equipment). Need both models without excessive complexity.")
         (decision . "ProbabilityModel with :independent (default) and :dependent modes. Independent uses Π(1 - p). Dependent uses barrier dependency symbols to identify shared-cause groups.")
         (consequences . "Positive: Handles common-cause failures, maintains simplicity for independent cases. Negative: Dependency model requires user annotation, no auto-detection of shared causes."))
       (adr-005
         (title . "Monte Carlo simulation with user-defined distributions")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Point estimates hide uncertainty. Barrier effectiveness varies (maintenance, operator skill). Need to quantify uncertainty without requiring full Bayesian model.")
         (decision . "simulate() function samples barrier effectiveness from beta/triangular distributions. User specifies per-barrier distributions, system runs N samples, returns mean and distribution.")
         (consequences . "Positive: Quantifies uncertainty, standard Monte Carlo approach. Negative: Requires distribution parameter estimation, computationally expensive for large N."))
       (adr-006
         (title . "Diagram export to Mermaid and GraphViz")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Bowtie diagrams are communication tools. Manual drawing error-prone. Need to generate diagrams from model data for presentations, reports, collaboration.")
         (decision . "to_mermaid() and to_graphviz() functions export model to diagram specs. Mermaid for web rendering, GraphViz for publication quality. Users adjust layout in tools.")
         (consequences . "Positive: Automated diagram generation, version control for diagrams. Negative: Layout quality depends on external tools, may need manual tweaking for complex models."))
       (adr-007
         (title . "JSON serialization as primary exchange format")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Need to integrate with web UIs, other tools, databases. Julia-specific formats (JLD2, BSON) not interoperable. JSON widely supported.")
         (decision . "JSON3 for read/write, generate JSON Schema for validation. Model schema allows UI builders to create conformant models without Julia knowledge.")
         (consequences . "Positive: Wide interoperability, schema validation, web-ready. Negative: JSON verbose for large models, no type safety at serialization boundary."))
       (adr-008
         (title . "Template library for common risk scenarios")
         (status . accepted)
         (date . "2026-01-28")
         (context . "New users lack domain knowledge to build models from scratch. Common scenarios (process safety, cybersecurity) recur. Need starter models to reduce learning curve.")
         (decision . "template_model(:process_safety) and similar functions return pre-built models. Users customize for their context. Templates include realistic probabilities and barriers.")
         (consequences . "Positive: Lowers barrier to entry, best-practice examples, consistency across analyses. Negative: Templates may not fit all contexts, risk of cargo-cult usage without understanding."))
       (adr-009
         (title . "CSV import for simple data sources")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Many organizations have risk data in spreadsheets. Need simple import path. Full CSV parsing complex (domain-specific columns, formats).")
         (decision . "load_simple_csv() for basic key-value data. Document CSV schema for each domain. Users write custom parsers for complex formats.")
         (consequences . "Positive: Easy integration with existing data, simple implementation. Negative: Limited to simple formats, no standardized risk data CSV format, requires domain-specific work."))
       (adr-010
         (title . "Pure Julia implementation without C dependencies")
         (status . accepted)
         (date . "2026-01-28")
         (context . "Risk analysis not performance-critical like crypto. Julia's math libraries sufficient. Avoiding C deps simplifies deployment, cross-platform support.")
         (decision . "Implement all calculations in pure Julia. Use Distributions.jl for statistical functions, JSON3 for serialization. No C/Fortran libraries.")
         (consequences . "Positive: Easy deployment, no build toolchain, cross-platform by default. Negative: May be slower than C for very large models, but acceptable for typical use.")))

    (development-practices
      (code-style
        (formatter . "julia-format")
        (line-length . 100)
        (naming . "snake_case for functions, PascalCase for types")
        (comments . "Docstrings for public API, inline for formula explanations"))
      (security
        (data-validation . "Clamp probabilities to [0,1], check for NaN/Inf")
        (input-sanitization . "JSON schema validation for deserialized models")
        (threat-model . "Assumes trusted input data, focus on correct calculations"))
      (testing
        (unit-tests . "All public functions and structs")
        (property-tests . "Probability invariants (0 ≤ p ≤ 1, monotonicity)")
        (test-vectors . "Worked examples from risk analysis literature")
        (coverage-target . 85))
      (versioning
        (scheme . "SemVer")
        (compatibility . "Julia 1.9+"))
      (documentation
        (api-docs . "Docstrings in source, extracted to docs/")
        (examples . "README with quick start, templates documented")
        (theory . "Probability model explained in README")
        (integration . "JSON schema published for tool builders"))
      (branching
        (main-branch . "main")
        (feature-branches . "feat/*, fix/*")
        (release-process . "GitHub releases, Julia package registry")))

    (design-rationale
      (why-bowtie-methodology
        "Visual clarity: threats on left, consequences on right, barriers visible"
        "Industry standard in process safety, chemical engineering, aviation"
        "Separates prevention (left) from mitigation (right) - clarifies control strategy"
        "Complements fault tree analysis (FTA) and event tree analysis (ETA)")
      (why-transparent-calculations
        "Safety-critical contexts demand auditability"
        "Regulatory compliance requires explainable risk scores"
        "Users can validate formulas against domain standards"
        "Easier to customize for specific methodologies (NIST 800-30, ISO 31000)")
      (why-event-chains
        "Real failures progress through stages (initiation, escalation, outcome)"
        "Timeline view helps identify detection and intervention points"
        "Models lag between threat and top event, top event and consequence"
        "Supports dynamic risk analysis beyond static bowtie snapshots")
      (why-escalation-factors
        "Barriers don't fail randomly - degraded by stress, resource limits, complexity"
        "Models human factors (fatigue, training), environmental (weather), organizational (budget)"
        "Composable: multiple factors interact multiplicatively"
        "Encourages thinking about barrier robustness, not just nominal effectiveness")
      (why-monte-carlo
        "Point estimates hide uncertainty in risk scores"
        "Barrier effectiveness varies (maintenance quality, operator skill, conditions)"
        "Quantifies confidence intervals for risk management decisions"
        "Standard approach in probabilistic risk assessment (PRA)")
      (why-sensitivity-analysis
        "Identifies which parameters most influence risk score"
        "Guides data collection: focus on high-impact uncertain parameters"
        "Tornado charts standard in risk communication"
        "Supports 'what-if' analysis for risk mitigation strategies")
      (why-mermaid-graphviz-export
        "Bowties are communication tools for stakeholders, not just analysts"
        "Automated generation prevents errors in manual drawing"
        "Version control for diagrams alongside model data"
        "Mermaid for web, GraphViz for publication - covers all use cases")
      (why-json-not-binary
        "Interoperability with web UIs, databases, other tools"
        "Human-readable for debugging and manual inspection"
        "JSON Schema enables validation without Julia runtime"
        "Git-friendly: diffs work, can review model changes in PRs")
      (why-templates
        "New users need starting points, not blank canvas"
        "Encode domain best practices (process safety, cybersecurity)"
        "Consistency across organization when everyone starts from same templates"
        "Educational: show realistic probabilities and barrier structures")
      (why-pure-julia
        "Risk analysis not performance-critical - milliseconds vs. hours acceptable"
        "No build toolchain simplifies deployment on user machines"
        "Cross-platform by default (Windows, macOS, Linux, BSD)"
        "Ecosystem integration: easy to combine with other Julia tools (Plots, DataFrames)"))))

;; Helper function
(define (get-adr id)
  (let ((adrs (assoc-ref meta 'architecture-decisions)))
    (assoc-ref adrs id)))
