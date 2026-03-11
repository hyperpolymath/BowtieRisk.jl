# SONNET-TASKS.md — BowtieRisk.jl Completion Tasks

> **Generated:** 2026-02-12 by Opus audit
> **Purpose:** Unambiguous instructions for Sonnet to complete all stubs, TODOs, and placeholder code.
> **Honest completion before this file:** 72%

The Julia core (`src/BowtieRisk.jl`) is genuinely functional -- types, evaluate, simulate,
sensitivity_tornado, serialization, diagramming, templates, and CSV import all work and have
real implementations with real tests. However, there are significant problems elsewhere:
the RSR template files (ABI/FFI, contractiles, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md,
CITATIONS.adoc, examples, docs, ROADMAP.adoc) were never customized from the template and
still contain `{{PROJECT}}`, `{{project}}`, `{{OWNER}}`, `{{REPO}}`, `{{FORGE}}` placeholders.
Several files use the banned AGPL-3.0 license header instead of PMPL-1.0-or-later. The
`.machine_readable/` directory with SCM files is entirely missing. The Documenter.jl docs
reference a non-existent `api.md`. The test suite has dead code (testing for templates and
fields that do not exist). The examples directory contains ReScript SafeDOM code that has
nothing to do with BowtieRisk.jl.

---

## GROUND RULES FOR SONNET

1. Read this entire file before starting any task.
2. Do tasks in order listed. Earlier tasks unblock later ones.
3. After each task, run the verification command. If it fails, fix before moving on.
4. Do NOT mark done unless verification passes.
5. Update STATE.scm with honest completion percentages after each task.
6. Commit after each task: `fix(component): complete <description>`
7. Run full test suite after every 3 tasks: `cd /var/mnt/eclipse/repos/BowtieRisk.jl && julia --project=. -e 'using Pkg; Pkg.test()'`

---

## TASK 1: Fix AGPL-3.0 license headers to PMPL-1.0-or-later (CRITICAL)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/examples/SafeDOMExample.res` (line 1)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ffi/zig/build.zig` (line 2)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ffi/zig/src/main.zig` (line 6)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ffi/zig/test/integration_test.zig` (line 2)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/docs/CITATIONS.adoc` (line 13)

**Problem:** These files use `SPDX-License-Identifier: AGPL-3.0-or-later` or `license = {AGPL-3.0-or-later}`. Per CLAUDE.md license policy, AGPL-3.0 is NEVER allowed. All hyperpolymath original code must use PMPL-1.0-or-later.

**What to do:**
1. In each file listed, replace `AGPL-3.0-or-later` with `PMPL-1.0-or-later`.
2. In `docs/CITATIONS.adoc` line 13, change `license = {AGPL-3.0-or-later}` to `license = {PMPL-1.0-or-later}`.
3. Also update the citation to reference `BowtieRisk.jl` instead of `RSR-template-repo` (lines 8-15) -- fix `author`, `title`, and `url` fields.

**Verification:**
```bash
grep -rn "AGPL" /var/mnt/eclipse/repos/BowtieRisk.jl/ | grep -v ".git/" | grep -v "SONNET-TASKS"
# Expected: zero lines of output
```

---

## TASK 2: Replace all RSR template placeholders (CRITICAL)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/CONTRIBUTING.md` (lines 2, 3, 9, 10, 20, 89-92)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/CODE_OF_CONDUCT.md` (lines 9, 10, 313)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/SECURITY.md` (lines 9, 10, 43, 206, 325, 374, 386, 387)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ABI-FFI-README.md` (lines 3, 29, 42, 53, 70, 74, 202, 225, 228, 231, 233, 237, 244, 250, 267, 269-271, 276, 279, 282, 290, 293, 299, 304, 358)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/src/abi/Types.idr` (lines 6, 11)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/src/abi/Layout.idr` (lines 8, 10)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/src/abi/Foreign.idr` (lines 9, 11, 12, 23, 35, 49, 72, 77, 98, 125, 152, 164, 185, 211)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ffi/zig/build.zig` (lines 1, 12, 23, 35, 36, 82)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ffi/zig/src/main.zig` (lines 1, 12, 54, 73, 89, 113, 135, 148, 184, 198, 203, 215, 246, 256, 257, 259, 263, 266, 271)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ffi/zig/test/integration_test.zig` (lines 1, 10-17, 24-25, 31-32, 34, 39, 48-49, 51, 56, 65-66, 68-69, 75, 84, 86, 96-97, 99, 110, 117, 129-130, 132-133, 138-139, 143, 145-146, 150, 158-159, 168)

**Problem:** Dozens of files still contain `{{PROJECT}}`, `{{project}}`, `{{OWNER}}`, `{{REPO}}`, `{{FORGE}}` template placeholders from the RSR template repo.

**What to do:**
1. Replace `{{PROJECT}}` with `BowtieRisk` (used in Idris module names, Zig comments)
2. Replace `{{project}}` with `bowtierisk` (used in C function names, library names)
3. Replace `{{OWNER}}` with `hyperpolymath`
4. Replace `{{REPO}}` with `BowtieRisk.jl`
5. Replace `{{FORGE}}` with `github.com`
6. Replace `{{SECURITY_EMAIL}}` with `jonathan.jewell@open.ac.uk` (in SECURITY.md)
7. Do a global search to confirm zero remaining `{{` patterns.

**Verification:**
```bash
grep -rn '{{' /var/mnt/eclipse/repos/BowtieRisk.jl/ --include="*.md" --include="*.adoc" --include="*.idr" --include="*.zig" --include="*.res" --include="*.json" | grep -v ".git/" | grep -v "SONNET-TASKS"
# Expected: zero lines of output
```

---

## TASK 3: Remove irrelevant SafeDOM example, add actual Julia example (HIGH)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/examples/SafeDOMExample.res` (DELETE)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/examples/web-project-deno.json` (DELETE)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/examples/basic_bowtie.jl` (CREATE)

**Problem:** The `examples/` directory contains a ReScript SafeDOM example and a Deno config file. Neither has anything to do with BowtieRisk.jl. These are template leftovers.

**What to do:**
1. Delete `examples/SafeDOMExample.res` and `examples/web-project-deno.json`.
2. Create `examples/basic_bowtie.jl` with a working example that:
   - Builds a simple bowtie model (use the process_safety template or construct manually)
   - Calls `evaluate()` and prints the summary
   - Runs `simulate()` with Beta and Triangular distributions
   - Generates a tornado chart
   - Writes a markdown report
   - Exports Mermaid and GraphViz diagrams
   - Shows JSON round-trip (write_model_json / read_model_json)
3. Add SPDX header `# SPDX-License-Identifier: PMPL-1.0-or-later` at top.

**Verification:**
```julia
cd("/var/mnt/eclipse/repos/BowtieRisk.jl")
include("examples/basic_bowtie.jl")
# Expected: runs without error, prints summary data, creates temporary output files
```

---

## TASK 4: Create missing .machine_readable/ directory with SCM files (HIGH)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/.machine_readable/STATE.scm` (CREATE)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/.machine_readable/META.scm` (CREATE)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/.machine_readable/ECOSYSTEM.scm` (CREATE)

**Problem:** The `.machine_readable/` directory is entirely missing. Per CLAUDE.md checkpoint file protocol, every repo MUST have STATE.scm, META.scm, and ECOSYSTEM.scm in `.machine_readable/`. They must NEVER be in the repository root.

**What to do:**
1. Create directory `.machine_readable/`.
2. Create `STATE.scm` with:
   - metadata section (name: BowtieRisk.jl, version: 1.0.0, language: Julia)
   - current-position section (phase: production, completion: 72%)
   - blockers: template placeholders, missing docs, missing examples
   - critical-next-actions: complete SONNET-TASKS
3. Create `META.scm` with:
   - architecture-decisions: Julia structs are immutable for safety, JSON3 for serialization, Monte Carlo via Distributions.jl
   - development-practices: test-driven, PMPL-1.0-or-later license
4. Create `ECOSYSTEM.scm` with:
   - type: julia-package
   - purpose: bowtie risk modeling framework
   - related-projects: Distributions.jl, JSON3.jl
   - position-in-ecosystem: standalone risk analysis tool
5. Use Guile Scheme s-expression format consistent with other repos.

**Verification:**
```bash
test -f /var/mnt/eclipse/repos/BowtieRisk.jl/.machine_readable/STATE.scm && \
test -f /var/mnt/eclipse/repos/BowtieRisk.jl/.machine_readable/META.scm && \
test -f /var/mnt/eclipse/repos/BowtieRisk.jl/.machine_readable/ECOSYSTEM.scm && \
echo "PASS" || echo "FAIL"
```

---

## TASK 5: Fix Documenter.jl -- create missing api.md page (MEDIUM)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/docs/src/api.md` (CREATE)
- `/var/mnt/eclipse/repos/BowtieRisk.jl/docs/src/index.md` (line 17: "Examples coming soon")
- `/var/mnt/eclipse/repos/BowtieRisk.jl/docs/make.jl` (already references `api.md` at line 12)

**Problem:** `docs/make.jl` at line 12 declares `pages = ["Home" => "index.md", "API" => "api.md"]` but `docs/src/api.md` does not exist. The docs build will fail. Also, `index.md` line 17 says "Examples coming soon" which is a placeholder.

**What to do:**
1. Create `docs/src/api.md` with Documenter.jl `@docs` blocks for all exported symbols:
   - Hazard, Threat, TopEvent, Consequence, Barrier, EscalationFactor
   - ProbabilityModel, ThreatPath, ConsequencePath, BowtieModel
   - BarrierDistribution, SimulationResult
   - Event, EventChain, chain_probability
   - evaluate, to_mermaid, to_graphviz
   - simulate, sensitivity_tornado
   - report_markdown, write_report_markdown, write_tornado_csv
   - write_model_json, read_model_json
   - list_templates, template_model
   - write_schema_json, model_schema
   - load_simple_csv
2. In `docs/src/index.md`, replace "# Examples coming soon" with an actual brief example (copy from README.md Quick Start section, abbreviated).

**Verification:**
```julia
cd("/var/mnt/eclipse/repos/BowtieRisk.jl")
using Pkg; Pkg.activate("docs")
Pkg.develop(path=".")
Pkg.add("Documenter")
include("docs/make.jl")
# Expected: docs build succeeds without warnings about missing pages
```

---

## TASK 6: Fix test suite dead code and add missing template tests (MEDIUM)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/test/runtests.jl` (lines 118, 157-167)

**Problem:**
- Line 118: `@test hasproperty(sim, :top_event_std) || true` -- `SimulationResult` does NOT have a `top_event_std` field (line 141-145 of BowtieRisk.jl). `hasproperty` will return `false`, but `|| true` makes the test always pass. This is dead code that hides a missing feature.
- Lines 157-167: The loop tests templates `:cybersecurity` and `:operational`, but `template_model` only supports `:process_safety` and `:cyber_incident`. The `try/catch` silently swallows the errors with `@test true`. This masks the fact that the test is referencing wrong template names.

**What to do:**
1. Line 118: Either implement `top_event_std` in `SimulationResult` (add standard deviation calculation in `simulate`) OR remove the dead test. Recommendation: add `top_event_std::Float64` to `SimulationResult` (line 141) and compute it in `simulate` (line 304).
   - Add field: `top_event_std::Float64` to `SimulationResult`
   - Compute: `top_std = sqrt(sum((v - top_mean)^2 for v in top_vals) / length(top_vals))` in `simulate`
   - Update the constructor call at line 304 to include the std value
   - Fix test line 118 to: `@test sim.top_event_std >= 0.0`
2. Lines 157-167: Fix template names to match actual implementations:
   - Replace `:cybersecurity` with `:cyber_incident`
   - Replace `:operational` with... there is no third template. Remove `:operational` from the loop or implement an `:operational` template in `template_model`.
   - Remove the `try/catch` -- templates that exist should not throw.

**Verification:**
```julia
cd("/var/mnt/eclipse/repos/BowtieRisk.jl")
using Pkg; Pkg.test()
# Expected: all tests pass, no silently caught errors
```

---

## TASK 7: Customize ROADMAP.adoc from template boilerplate (LOW)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/ROADMAP.adoc`

**Problem:** `ROADMAP.adoc` still contains the RSR template boilerplate ("YOUR Template Repo Roadmap", "Initial development phase", generic milestones). Meanwhile `ROADMAP.md` has real BowtieRisk.jl-specific content. Having two conflicting ROADMAP files is confusing.

**What to do:**
1. Delete `ROADMAP.adoc` entirely. The `ROADMAP.md` already has comprehensive, project-specific roadmap content.
2. Alternatively, if both formats are needed: replace the content of `ROADMAP.adoc` with an AsciiDoc version of `ROADMAP.md` content and delete `ROADMAP.md`. Pick ONE format.

**Verification:**
```bash
ls /var/mnt/eclipse/repos/BowtieRisk.jl/ROADMAP*
# Expected: exactly one ROADMAP file (either .md or .adoc, not both)
```

---

## TASK 8: Customize CITATIONS.adoc for BowtieRisk.jl (LOW)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/docs/CITATIONS.adoc`

**Problem:** Lines 8-15 still reference `rsr-template-repo` and `Polymath, Hyper` as author. This is the template boilerplate.

**What to do:**
1. Replace `rsr-template-repo_2025` with `bowtierisk_jl_2025` (BibTeX key)
2. Replace `author = {Polymath, Hyper}` with `author = {Jewell, Jonathan D.A.}`
3. Replace `title = {RSR-template-repo}` with `title = {BowtieRisk.jl}`
4. Replace year `2025` with `2026`
5. Replace all `url` values from `https://github.com/hyperpolymath/RSR-template-repo` to `https://github.com/hyperpolymath/BowtieRisk.jl`
6. Update Harvard, OSCOLA, MLA, APA 7 sections similarly.

**Verification:**
```bash
grep -c "RSR-template-repo\|Polymath, Hyper\|Polymath, H\.\|Hyper Polymath" /var/mnt/eclipse/repos/BowtieRisk.jl/docs/CITATIONS.adoc
# Expected: 0
```

---

## TASK 9: Customize README.adoc from template boilerplate (LOW)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/README.adoc`

**Problem:** `README.adoc` still says "This is your repo - don't forget to rename me!" (line 3) and contains RSR template instructions about SafeDOM, ReScript, Idris2, etc. None of this is relevant to BowtieRisk.jl. Meanwhile `README.md` has the real project README.

**What to do:**
1. Delete `README.adoc` entirely. `README.md` already exists with complete, correct content.
2. GitHub will display `README.md` by default.

**Verification:**
```bash
test ! -f /var/mnt/eclipse/repos/BowtieRisk.jl/README.adoc && test -f /var/mnt/eclipse/repos/BowtieRisk.jl/README.md && echo "PASS" || echo "FAIL"
```

---

## TASK 10: Add consequence-side sensitivity to sensitivity_tornado (LOW)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/src/BowtieRisk.jl` (lines 310-336)

**Problem:** `sensitivity_tornado` only perturbs barriers on `model.threat_paths` (lines 314-331). It completely ignores barriers on `model.consequence_paths`. This means mitigative barriers are invisible to the sensitivity analysis, which defeats the purpose of a bowtie (which has barriers on both sides).

**What to do:**
1. After the existing threat_paths loop (line 332), add a second loop over `model.consequence_paths`:
   ```julia
   for (pidx, path) in enumerate(model.consequence_paths)
       for (bidx, barrier) in enumerate(path.barriers)
           lower = clamp(barrier.effectiveness - delta, 0.0, 1.0)
           upper = clamp(barrier.effectiveness + delta, 0.0, 1.0)
           low_barrier = Barrier(barrier.name, lower, barrier.kind, barrier.description, barrier.degradation, barrier.dependency)
           high_barrier = Barrier(barrier.name, upper, barrier.kind, barrier.description, barrier.degradation, barrier.dependency)
           low_cons = deepcopy(model.consequence_paths)
           high_cons = deepcopy(model.consequence_paths)
           low_cons[pidx].barriers[bidx] = low_barrier
           high_cons[pidx].barriers[bidx] = high_barrier
           low_model = BowtieModel(model.hazard, model.top_event, model.threat_paths, low_cons, model.probability_model)
           high_model = BowtieModel(model.hazard, model.top_event, model.threat_paths, high_cons, model.probability_model)
           push!(results, (barrier.name, evaluate(low_model).top_event_probability, evaluate(high_model).top_event_probability))
       end
   end
   ```
2. Note: The consequence-side barriers do NOT affect `top_event_probability` -- they affect `consequence_probabilities`. Consider whether the tornado should return consequence-level sensitivity instead. If so, change the pushed tuple to include consequence impact, or add a separate function `sensitivity_tornado_consequences`.
3. At minimum, add a test that verifies mitigative barriers appear in tornado output when there are consequence-path barriers.

**Verification:**
```julia
using BowtieRisk
model = template_model(:process_safety)
tornado = sensitivity_tornado(model; delta=0.1)
barrier_names = [t[1] for t in tornado]
@assert :GasDetection in barrier_names "Mitigative barrier GasDetection should appear in tornado"
```

---

## TASK 11: Add missing `api.md` Documenter pages reference for BowtieSummary (LOW)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/src/BowtieRisk.jl` (lines 7-17 exports, line 244)

**Problem:** `BowtieSummary` (line 244) is a return type from `evaluate()` but is NOT exported. Users calling `evaluate(model)` get back a `BowtieSummary` struct and must access `.top_event_probability`, `.threat_residuals`, `.consequence_probabilities`, `.consequence_risks` -- but they cannot reference the type by name without `BowtieRisk.BowtieSummary`.

**What to do:**
1. Add `BowtieSummary` to the export list at line 8 or 9.
2. If you created `api.md` in Task 5, add a `@docs BowtieSummary` entry.

**Verification:**
```julia
using BowtieRisk
summary = evaluate(template_model(:process_safety))
@assert summary isa BowtieSummary "BowtieSummary should be exported and accessible"
```

---

## TASK 12: Model schema is too shallow -- add property definitions (LOW)

**Files:**
- `/var/mnt/eclipse/repos/BowtieRisk.jl/src/BowtieRisk.jl` (lines 432-446)

**Problem:** `model_schema()` returns a JSON schema where every property is just `Dict("type" => "object")` or `Dict("type" => "array")`. This is not useful for validation -- it would accept any JSON object as a valid bowtie model. The schema should define nested properties for hazard, threat_paths, consequence_paths, etc.

**What to do:**
1. Expand the schema to define nested properties. For example:
   - `hazard` should have `properties: { name: { type: "string" }, description: { type: "string" } }`
   - `threat_paths` items should have `threat`, `barriers`, `escalation_factors`
   - `barriers` items should have `name`, `effectiveness`, `kind`, `description`, `degradation`, `dependency`
2. This should match what `write_model_json` actually produces (lines 566-614).
3. Add `"additionalProperties" => false` where appropriate.

**Verification:**
```julia
using BowtieRisk, JSON3
schema = model_schema()
# Check hazard has nested properties
@assert haskey(schema["properties"]["hazard"], "properties") "hazard schema should have nested properties"
@assert haskey(schema["properties"]["hazard"]["properties"], "name") "hazard should require name"
```

---

## FINAL VERIFICATION

After completing all tasks, run:

```bash
cd /var/mnt/eclipse/repos/BowtieRisk.jl

# 1. All tests pass
julia --project=. -e 'using Pkg; Pkg.test()'

# 2. No template placeholders remain
grep -rn '{{' . --include="*.md" --include="*.adoc" --include="*.idr" --include="*.zig" --include="*.res" --include="*.json" --include="*.jl" | grep -v ".git/" | grep -v "SONNET-TASKS"

# 3. No AGPL references remain
grep -rn "AGPL" . | grep -v ".git/" | grep -v "SONNET-TASKS"

# 4. SCM files exist
ls -la .machine_readable/STATE.scm .machine_readable/META.scm .machine_readable/ECOSYSTEM.scm

# 5. No duplicate README/ROADMAP
ls README* ROADMAP*

# 6. Example runs
julia --project=. examples/basic_bowtie.jl

# 7. BowtieSummary is exported
julia --project=. -e 'using BowtieRisk; s = evaluate(template_model(:process_safety)); @assert s isa BowtieSummary'

# 8. Docs build (optional, requires Documenter.jl)
# julia --project=docs docs/make.jl
```

All 8 checks must pass. If any fail, trace back to the relevant task and fix.
