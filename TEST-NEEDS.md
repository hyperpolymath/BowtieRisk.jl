<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# TEST-NEEDS: BowtieRisk.jl

## CRG Grade: C — ACHIEVED 2026-04-04

## Current State

| Category | Count | Details |
|----------|-------|---------|
| **Source modules** | 2 | 857 lines |
| **Test files** | 1 | 575 lines, 101 @test/@testset |
| **Benchmarks** | 0 | None |

## What's Missing

- [ ] **E2E**: No end-to-end risk assessment pipeline test
- [ ] **Performance**: No benchmarks
- [ ] **Error handling**: No tests for incomplete risk data, inconsistent threat models

## FLAGGED ISSUES
- **101 tests for 2 modules = 50.5 tests/module** -- excellent
- **0 benchmarks**

## Priority: P3 (LOW)

## FAKE-FUZZ ALERT

- `tests/fuzz/placeholder.txt` is a scorecard placeholder inherited from rsr-template-repo — it does NOT provide real fuzz testing
- Replace with an actual fuzz harness (see rsr-template-repo/tests/fuzz/README.adoc) or remove the file
- Priority: P2 — creates false impression of fuzz coverage
