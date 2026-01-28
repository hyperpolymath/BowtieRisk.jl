;; SPDX-License-Identifier: PMPL-1.0-or-later
;; STATE.scm - Project state tracking for BowtieRisk.jl

(define-module (state bowtierisk)
  #:use-module (ice-9 match)
  #:export (state get-completion-percentage get-blockers get-milestone))

(define state
  '((metadata
      (version . "0.1.0")
      (schema-version . "1.0.0")
      (created . "2026-01-28")
      (updated . "2026-01-28")
      (project . "BowtieRisk.jl")
      (repo . "https://github.com/hyperpolymath/BowtieRisk.jl"))

    (project-context
      (name . "BowtieRisk.jl")
      (tagline . "Bowtie risk modeling with event chains, escalation factors, and Monte Carlo simulation")
      (tech-stack . ("Julia" "JSON3" "Distributions" "Guix" "Nix"))
      (target-platforms . ("Linux" "macOS" "Windows" "BSD")))

    (current-position
      (phase . "functional-mvp")
      (overall-completion . 80)
      (components
        ((name . "Core data structures")
         (status . "complete")
         (completion . 100)
         (notes . "Hazard, Threat, TopEvent, Consequence, Barrier, EscalationFactor, EventChain"))
        ((name . "Probability calculations")
         (status . "implemented")
         (completion . 95)
         (notes . "Independent and dependent models, barrier effectiveness, chain probability"))
        ((name . "Monte Carlo simulation")
         (status . "implemented")
         (completion . 90)
         (notes . "Beta/triangular distributions, configurable samples, result aggregation"))
        ((name . "Sensitivity analysis")
         (status . "implemented")
         (completion . 85)
         (notes . "Tornado charts with delta-based parameter variation"))
        ((name . "Diagramming support")
         (status . "implemented")
         (completion . 90)
         (notes . "Mermaid flowchart and GraphViz DOT export"))
        ((name . "JSON serialization")
         (status . "complete")
         (completion . 100)
         (notes . "JSON3-based read/write with schema export"))
        ((name . "Templates")
         (status . "implemented")
         (completion . 70)
         (notes . "Process safety template, needs more domain templates"))
        ((name . "Reporting")
         (status . "implemented")
         (completion . 85)
         (notes . "Markdown reports, CSV tornado data export"))
        ((name . "CSV import")
         (status . "basic")
         (completion . 50)
         (notes . "Simple CSV loader, needs domain-specific parsers"))
        ((name . "Documentation")
         (status . "complete")
         (completion . 90)
         (notes . "Comprehensive README with examples, API reference"))
        ((name . "Test coverage")
         (status . "good")
         (completion . 80)
         (notes . "All major features tested, needs edge case coverage"))))

      (working-features
        "Bowtie model construction and evaluation"
        "Independent and dependent probability models"
        "Event chain analysis with barriers"
        "Monte Carlo simulation with distributions"
        "Sensitivity tornado charts"
        "Mermaid and GraphViz diagram export"
        "JSON read/write with schema"
        "Markdown and CSV reporting"
        "Process safety template"
        "Escalation factor modeling"))

    (route-to-mvp
      (milestones
        ((name . "Core functionality")
         (target-date . "2026-01-28")
         (status . "complete")
         (items
           "✓ Core data structures implemented"
           "✓ Probability calculations working"
           "✓ JSON serialization complete"
           "✓ Diagram export (Mermaid/GraphViz)"
           "✓ Basic test coverage"))
        ((name . "Extended features")
         (target-date . "2026-02-10")
         (status . "mostly-complete")
         (items
           "✓ Monte Carlo simulation"
           "✓ Sensitivity analysis"
           "✓ Reporting (Markdown/CSV)"
           "Add more templates (cybersecurity, financial, operational)"
           "Enhance CSV import for domain-specific formats"))
        ((name . "Quality and documentation")
         (target-date . "2026-02-20")
         (status . "in-progress")
         (items
           "Expand test coverage to >90%"
           "Add property-based tests for probability calculations"
           "Create user guide with real-world examples"
           "Add NIST 800-30 risk framework alignment guide"))
        ((name . "v0.2.0 Release")
         (target-date . "2026-03-01")
         (status . "planned")
         (items
           "All templates implemented"
           "Enhanced CSV import/export"
           "Interactive visualization support (PlotlyJS/Makie)"
           "Integration with Causals.jl for causal modeling"
           "Performance benchmarks and optimization"))))

    (blockers-and-issues
      (critical
        ())
      (high
        ())
      (medium
        ("Need more domain-specific templates (cybersecurity, financial, operational)"
         "CSV import limited to simple format, needs domain parsers"
         "No interactive visualization yet (planned PlotlyJS/Makie integration)"))
      (low
        ("Property-based tests for probability edge cases"
         "Performance profiling for large models"
         "NIST 800-30 alignment documentation")))

    (critical-next-actions
      (immediate
        "Add cybersecurity template (data breach scenario)"
        "Add financial risk template (operational loss)"
        "Expand test coverage for edge cases")
      (this-week
        "Implement domain-specific CSV parsers"
        "Add property-based tests for probability calculations"
        "Create user guide with real-world scenarios")
      (this-month
        "Integrate with Causals.jl for causal analysis"
        "Add interactive visualization support"
        "Performance optimization for large models"))

    (session-history
      ((date . "2026-01-28")
       (description . "Initial BowtieRisk.jl SCM file creation")
       (accomplishments
         "Analyzed existing codebase (662 LOC)"
         "Created STATE.scm with accurate project status"
         "Identified working features and blockers"
         "Planned roadmap to v0.2.0")))))

;; Helper functions
(define (get-completion-percentage)
  (assoc-ref (assoc-ref state 'current-position) 'overall-completion))

(define (get-blockers)
  (assoc-ref state 'blockers-and-issues))

(define (get-milestone name)
  (let ((milestones (assoc-ref (assoc-ref state 'route-to-mvp) 'milestones)))
    (find (lambda (m) (equal? (assoc-ref m 'name) name)) milestones)))
