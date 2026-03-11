<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-02-19 -->

# BowtieRisk.jl — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │          EXTERNALS / ECOSYSTEM          │
                        ├─────────────────────────────────────────┤
                        │  ┌────────────┐      ┌────────────┐     │
                        │  │ Mermaid/GV │ ◀─── │   JSON3    │     │
                        │  │ (Diagrams) │      │ (Serializ.)│     │
                        │  └─────▲──────┘      └─────▲──────┘     │
                        │        │                   │            │
                        └────────┼───────────────────┼────────────┘
                                 │                   │
                                 ▼                   │
                        ┌────────────────────────────┼────────────┐
                        │           APPLICATION LAYER             │
                        ├─────────────────────────────────────────┤
                        │  ┌──────────────────┐      ┌──────────┐ │
                        │  │  Bowtie Model    │      │ Template │ │
                        │  │  (Structures)    │ ───▶ │  Models  │ │
                        │  └────────┬─────────┘      └─────┬────┘ │
                        │           │                      │      │
                        │  ┌────────▼─────────┐      ┌─────▼────┐ │
                        │  │  Probability     │      │ Monte    │ │
                        │  │     Model        │ ───▶ │ Carlo    │ │
                        │  └────────┬─────────┘      └─────┬────┘ │
                        │           │                      │      │
                        │  ┌────────▼─────────┐      ┌─────▼────┐ │
                        │  │ Sensitivity      │      │ Report   │ │
                        │  │ (Tornado)        │ ◀──▶ │ Generator│ │
                        │  └──────────────────┘      └──────────┘ │
                        └──────────────────────┬──────────────────┘
                                               │
                        ┌──────────────────────▼──────────────────┐
                        │         REPO INFRASTRUCTURE             │
                        │  .machine_readable/ (state)             │
                        │  .github/workflows/ (RSR Gate)          │
                        │  Project.toml                           │
                        └─────────────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE MODEL
  Core Data Structures              ██████████ 100%    Hazard, Threat, TopEvent, etc.
  Model Evaluation                  ██████████ 100%    evaluate(), residual risk
  JSON Serialization                ██████████ 100%    JSON3 integration

ANALYTICS & SIMULATION
  Monte Carlo Simulation            ██████████ 100%    Distributions.jl integration
  Sensitivity Analysis              ██████░░░░  60%    Threat-side only
  Template Models                   █████░░░░░  50%    Process/Cyber done

REPORTING & INTEROP
  Export Formats                    █████████░  90%    Mermaid, GraphViz, Markdown
  CSV Import                        ████████░░  85%    Functional
  JSON Schema                       ████░░░░░░  40%    Needs nested definitions

REPO INFRASTRUCTURE
  .machine_readable/ (STATE.scm)    ██████████ 100%    Updated to v1.0.0
  .github/workflows/ (CI)           ██████████ 100%    RSR standard compliance
  Template Cleanup                  ██░░░░░░░░  20%    Placeholders remain

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            ███████░░░  ~72%   Production Phase (Stabilizing)
```

## Key Dependencies

```
Core Structures ──────► Model Evaluation ──────► Monte Carlo Sim
                                                     │
Export Formats ◀──────── Reporting ◀─────────────────┘
                                                     │
                                             Sensitivity Analysis
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
