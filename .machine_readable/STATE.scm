;; SPDX-License-Identifier: PMPL-1.0-or-later
;; STATE.scm - Project state tracking for BowtieRisk.jl

(define-module (state bowtierisk)
  #:use-module (ice-9 match)
  #:export (state get-completion-percentage get-blockers get-milestone))

(define state
  '((metadata
      (version . "1.0.0")
      (schema-version . "1.0.0")
      (created . "2025-01-17")
      (updated . "2026-02-12")
      (project . "BowtieRisk.jl")
      (repo . "https://github.com/hyperpolymath/BowtieRisk.jl"))

    (project-context
      (name . "BowtieRisk.jl")
      (tagline . "Formal bowtie risk modeling framework for Julia")
      (tech-stack . ("Julia" "JSON3" "Distributions.jl" "Documenter"))
      (target-platforms . ("Linux" "macOS" "Windows")))

    (current-position
      (phase . "production")
      (overall-completion . 72)
      (components
        ((name . "Core data structures")
         (status . "complete")
         (completion . 100)
         (notes . "Hazard, Threat, TopEvent, Consequence, Barrier, EscalationFactor"))
        ((name . "Model evaluation")
         (status . "complete")
         (completion . 100)
         (notes . "evaluate(), chain_probability(), residual risk calculation"))
        ((name . "Monte Carlo simulation")
         (status . "complete")
         (completion . 100)
         (notes . "simulate() with Beta/Triangular distributions, n_iterations"))
        ((name . "Sensitivity analysis")
         (status . "partial")
         (completion . 60)
         (notes . "sensitivity_tornado() only covers threat paths, not consequence paths"))
        ((name . "Template models")
         (status . "partial")
         (completion . 50)
         (notes . "process_safety and cyber_incident exist, operational missing"))
        ((name . "Export formats")
         (status . "complete")
         (completion . 90)
         (notes . "Mermaid, GraphViz, markdown reports, tornado CSV"))
        ((name . "JSON serialization")
         (status . "complete")
         (completion . 100)
         (notes . "write_model_json, read_model_json with JSON3"))
        ((name . "JSON Schema validation")
         (status . "partial")
         (completion . 40)
         (notes . "model_schema() too shallow, needs nested property definitions"))
        ((name . "CSV import")
         (status . "complete")
         (completion . 85)
         (notes . "load_simple_csv() functional"))
        ((name . "Documentation")
         (status . "partial")
         (completion . 60)
         (notes . "README.md complete, api.md missing, index.md has placeholder"))
        ((name . "Test suite")
         (status . "complete")
         (completion . 80)
         (notes . "Comprehensive tests but with dead code at lines 118, 157-167"))
        ((name . "RSR template cleanup")
         (status . "incomplete")
         (completion . 20)
         (notes . "14 files still have {{placeholders}}, duplicate README/ROADMAP files"))))

      (working-features
        "Bowtie model construction and evaluation"
        "Monte Carlo simulation with Distributions.jl"
        "Tornado chart sensitivity analysis (threat-side only)"
        "Template models (process_safety, cyber_incident)"
        "Mermaid and GraphViz diagram export"
        "Markdown report generation"
        "JSON serialization and deserialization"
        "CSV import for simple models"
        "Event chain probability calculation"
        "Barrier effectiveness modeling with degradation"))

    (route-to-mvp
      (milestones
        ((name . "RSR Template Compliance")
         (target-date . "2026-02-15")
         (status . "in-progress")
         (items
           "Fix all {{placeholder}} references"
           "Remove AGPL headers (use PMPL-1.0-or-later)"
           "Delete duplicate README/ROADMAP .adoc files"
           "Customize CITATIONS.adoc"
           "Create .machine_readable/ SCM files"))
        ((name . "Documentation Complete")
         (target-date . "2026-02-20")
         (status . "planned")
         (items
           "Create docs/src/api.md with @docs blocks"
           "Replace index.md placeholder with real example"
           "Add examples/basic_bowtie.jl"
           "Test Documenter.jl build"))
        ((name . "Test Suite Cleanup")
         (target-date . "2026-02-20")
         (status . "planned")
         (items
           "Implement top_event_std in SimulationResult"
           "Fix template test loop (wrong names)"
           "Add test for consequence-side sensitivity"
           "Remove dead || true tests"))
        ((name . "Feature Completeness")
         (target-date . "2026-03-01")
         (status . "planned")
         (items
           "Add consequence-side sensitivity to tornado"
           "Export BowtieSummary type"
           "Expand model_schema() with nested properties"
           "Add operational template to list_templates"))
        ((name . "v1.1.0 Release")
         (target-date . "2026-03-15")
         (status . "planned")
         (items
           "All template placeholders removed"
           "Documentation complete and tested"
           "Test coverage 95%+"
           "All SONNET-TASKS verified"
           "Julia General registry submission"))))

    (blockers-and-issues
      (critical
        ())
      (high
        ("RSR template placeholders in 14 files ({{PROJECT}}, {{OWNER}}, {{FORGE}})"
         "Missing .machine_readable/ directory (breaks checkpoint protocol)"
         "Duplicate documentation files (README.adoc, ROADMAP.adoc)"))
      (medium
        ("api.md missing for Documenter.jl"
         "Test suite has dead code (lines 118, 157-167)"
         "sensitivity_tornado ignores consequence paths"))
      (low
        ("BowtieSummary not exported"
         "model_schema() too shallow"
         "CITATIONS.adoc still has template boilerplate")))

    (critical-next-actions
      (immediate
        "Create .machine_readable/ directory with SCM files"
        "Replace {{placeholders}} in 14 files"
        "Delete SafeDOM example files"
        "Create examples/basic_bowtie.jl")
      (this-week
        "Create docs/src/api.md"
        "Fix test suite dead code"
        "Delete duplicate README.adoc and ROADMAP.adoc"
        "Customize CITATIONS.adoc")
      (this-month
        "Add consequence-side sensitivity analysis"
        "Export BowtieSummary"
        "Expand model_schema with nested properties"
        "Submit to Julia General registry"))

    (session-history
      ((date . "2026-02-12")
       (accomplishments
         "Created .machine_readable/ directory with STATE.scm, META.scm, ECOSYSTEM.scm"
         "Started SONNET-TASKS completion (12 tasks identified)")))))

;; Helper functions
(define (get-completion-percentage)
  "Get overall project completion percentage"
  (assoc-ref (assoc-ref state 'current-position) 'overall-completion))

(define (get-blockers priority)
  "Get blockers by priority (:critical, :high, :medium, :low)"
  (let ((blockers (assoc-ref state 'blockers-and-issues)))
    (assoc-ref blockers priority)))

(define (get-milestone name)
  "Get milestone by name"
  (let* ((route (assoc-ref state 'route-to-mvp))
         (milestones (assoc-ref route 'milestones)))
    (assoc name milestones)))
