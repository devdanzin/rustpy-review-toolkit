---
description: "Comprehensive soundness review of the RustPython interpreter's own Rust source. Runs the six agents in phased groups: discovery + preflight orientation, then the flagship panic-site auditor alongside unsafe-soundness and GC-traverse, then complexity and history, then synthesis."
argument-hint: "[scope] [aspects]"
allowed-tools: ["Bash", "Glob", "Grep", "Read", "Task"]
---

# Comprehensive RustPython Internal Review

Run an implementer-perspective review of the RustPython interpreter itself — the runtime, not extensions built with it. Discovery and a preflight orientation run first; every downstream agent reads the orientation.

**Arguments:** "$ARGUMENTS"

**Plugin root:** `<plugin_root>` is the `plugins/rustpy-review-toolkit/` directory — this command file's grandparent.

## Argument Parsing

**Scope** (path or glob): `.` or omitted → whole workspace; `crates/vm/src` → the interpreter core; `crates/stdlib/src` → the stdlib modules; a single file → just that file.

**Aspects** (which agents to run; default `all`):

| Aspect | Agent |
|--------|-------|
| `panic` | panic-site-auditor |
| `unsafe` | unsafe-soundness-auditor |
| `traverse` | gc-traverse-auditor |
| `complexity` | rust-complexity-analyzer |
| `history` | git-history-analyzer |
| `all` | every agent above |

## Workflow

### Phase 0: Discovery

```
python <plugin_root>/scripts/discover_rustpy.py <scope>
```

Print the profile (`version`, `in_scope_crates`, `crate_roles`, `threading_feature`, `is_shallow_clone`, `total_rs_files`). If `is_rustpython` is false, **halt** — this command requires the RustPython workspace. If `out_of_scope` is true (an embedder), halt likewise. If `is_shallow_clone` is true, warn that `git-history-analyzer` will under-report and recommend `git fetch --unshallow`.

### Phase 1: Preflight orientation

Dispatch `rustpy-internals-mapper`. Wait for its report at `reports/<target>_v1/preflight/rustpython_internals_map.md` before continuing. Every downstream agent reads this file — it carries the reachability tiers and the payload catalog.

### Phase 2A: Flagship + crown jewels

Dispatch in parallel:
- `panic-site-auditor` (the flagship — Python-reachable panics)
- `unsafe-soundness-auditor` (the object-model cast-inconsistency / transmute crown jewel)
- `gc-traverse-auditor` (experimental, first-class — GC completeness)

### Phase 2B: Quality and history

Dispatch in parallel:
- `rust-complexity-analyzer`
- `git-history-analyzer` (runs after the others so it can overlay their findings on churn)

### Phase 3: Synthesis

Aggregate every agent's report. Deduplicate findings surfaced by multiple agents (same file:line). Produce a unified summary at `reports/<target>_v1/SUMMARY.md`:

1. **Top FIX findings** across all agents (panic-site FIX + unsafe-soundness FIX first).
2. **Per-crate breakdown** of FIX / CONSIDER / POLICY / ACCEPTABLE counts.
3. **Per-agent links** to the detailed reports.
4. **The experimental caveat** on gc-traverse (0 fuzzer-confirmed instances).
5. **Calibration notes** observed across the run.

## Output

All findings go to `reports/<target>_v1/`. Summary at the top; per-agent reports in `agents/`; preflight in `preflight/`.

For maintainer-facing output (sharing back to RustPython upstream), follow `docs/writing-maintainer-facing-reports.md` and `WORKING_WITH_MAINTAINERS.md`. RustPython's object model is under active upstream churn — pin every `file:line` citation to the reviewed commit.
