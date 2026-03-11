;; SPDX-License-Identifier: PMPL-1.0-or-later
;; META.scm - Meta-level information for BowtieRisk.jl

(define-module (meta bowtierisk)
  #:export (meta))

(define meta
  '((schema-version . "1.0.0")
    (updated . "2026-02-12")

    (architecture-decisions
      ((id . "ADR-001")
       (title . "Use immutable Julia structs for safety")
       (status . "accepted")
       (date . "2025-01-15")
       (context . "Bowtie models represent safety-critical risk analysis. Mutations could invalidate calculations.")
       (decision . "All core structs (Hazard, Threat, Barrier, etc.) are immutable. Use deepcopy for modifications.")
       (consequences . "Prevents accidental state changes, ensures reproducible simulations, slight memory overhead"))

      ((id . "ADR-002")
       (title . "JSON3 for serialization over BSON/JLD2")
       (status . "accepted")
       (date . "2025-01-17")
       (context . "Need human-readable model interchange format for auditing and version control.")
       (decision . "Use JSON3.jl for write_model_json/read_model_json. Avoid binary formats like BSON.")
       (consequences . "Models are text-based and git-friendly, larger file sizes than binary, slower I/O"))

      ((id . "ADR-003")
       (title . "Monte Carlo via Distributions.jl")
       (status . "accepted")
       (date . "2025-01-18")
       (context . "Need uncertainty quantification for barrier effectiveness.")
       (decision . "Use Distributions.jl Beta and Triangular distributions. Avoid custom RNG implementations.")
       (consequences . "Leverages battle-tested library, supports many distributions, standard API"))

      ((id . "ADR-004")
       (title . "Mermaid for primary diagram format")
       (status . "accepted")
       (date . "2025-01-20")
       (context . "Need lightweight, text-based diagram format for documentation and CI.")
       (decision . "Primary export is Mermaid flowchart syntax. GraphViz DOT as secondary option.")
       (consequences . "Works with Markdown renderers (GitHub, GitLab), easy to version control, limited layout control"))

      ((id . "ADR-005")
       (title . "Template models for domain-specific patterns")
       (status . "accepted")
       (date . "2025-01-22")
       (context . "Common risk scenarios (process safety, cybersecurity) have standard threat/consequence patterns.")
       (decision . "Provide template_model(:process_safety) and similar for quick starts.")
       (consequences . "Reduces boilerplate for common use cases, need to maintain templates as library evolves"))

      ((id . "ADR-006")
       (title . "Naive barrier independence assumption")
       (status . "accepted")
       (date . "2025-01-25")
       (context . "Modeling barrier dependencies increases complexity significantly.")
       (decision . "Initial version assumes barriers fail independently. dependency field is metadata only.")
       (consequences . "Simple implementation, may underestimate risk for correlated failures, users warned in docs"))

      ((id . "ADR-007")
       (title . "No automatic barrier degradation over time")
       (status . "accepted")
       (date . "2025-01-28")
       (context . "Time-dependent barrier effectiveness would require temporal modeling.")
       (decision . "degradation field is static metadata. Users must update manually or run separate simulation.")
       (consequences . "Simpler model, less accurate for long-term scenarios, may add time-series in v2.0")))

    (development-practices
      ((name . "Test-driven development")
       (description . "All new features require tests before merging. Target 85%+ coverage.")
       (status . "active"))

      ((name . "Semantic versioning")
       (description . "Follow SemVer 2.0 strictly. Breaking changes increment major version.")
       (status . "active"))

      ((name . "Julia General registry compliance")
       (description . "Follow Julia package naming (no dashes), use Project.toml compat bounds.")
       (status . "active"))

      ((name . "PMPL-1.0-or-later licensing")
       (description . "All original code uses Palimpsest License. SPDX headers on all files.")
       (status . "active"))

      ((name . "RSR template compliance")
       (description . "Follow hyperpolymath RSR standards: .machine_readable/ SCM files, AI.a2ml, standard workflows.")
       (status . "in-progress"))

      ((name . "Immutable data structures")
       (description . "Core model structs are immutable for safety. Use functional update patterns.")
       (status . "active")))

    (design-rationale
      ((topic . "Why bowtie over fault tree or event tree")
       (reasoning . "Bowties explicitly model both preventive (threat-side) and mitigative (consequence-side) barriers in a single diagram. Fault trees focus on causes, event trees on outcomes. Bowties show the complete picture: causes → event → outcomes with barriers on both sides.")
       (tradeoffs . "More complex than single-sided analysis, harder to automate than pure probability trees"))

      ((topic . "Why Julia over Python for risk modeling")
       (reasoning . "Julia offers type safety (structs prevent data errors), native performance (Monte Carlo simulations are fast), multiple dispatch (extensible models), and package ecosystem (Distributions.jl). Python would require mypy + numba for similar benefits.")
       (tradeoffs . "Smaller user base than Python, fewer pre-built risk libraries"))

      ((topic . "Naive barrier effectiveness composition")
       (reasoning . "Barriers in series use product rule (1 - effectiveness_A) * (1 - effectiveness_B). This assumes independence and gives residual probability. Simple to understand and compute.")
       (tradeoffs . "Underestimates risk if barriers have common-cause failures or dependencies. Users must model these separately if needed."))

      ((topic . "JSON over custom DSL")
       (reasoning . "JSON is universal, has strong tooling (editors, validators, parsers), and integrates with web APIs. A custom DSL would require parser maintenance and reduce interoperability.")
       (tradeoffs . "Verbose for humans (use templates instead), no syntax-level validation of bowtie semantics")))))
