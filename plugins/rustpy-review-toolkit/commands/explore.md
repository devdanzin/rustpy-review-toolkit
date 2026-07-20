---
description: "Comprehensive soundness review of the RustPython interpreter's own Rust source. Runs the thirteen agents in phased groups: discovery + preflight orientation, the flagship panic-site auditor alongside unsafe-soundness and GC-traverse, the v0.2 class-expansion agents (thread-safety, debug-format, capi-panic-boundary, ctypes-ffi, recursion-guard, eager-collect-parity, uninitialized-object), then complexity and history, then synthesis."
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
| `thread-safety` | thread-safety-auditor |
| `debug-format` | debug-format-auditor |
| `capi` | capi-panic-boundary |
| `ctypes` | ctypes-ffi-auditor |
| `recursion` | recursion-guard-auditor |
| `eager-collect` | eager-collect-parity |
| `uninit` | uninitialized-object-auditor |
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

### Phase 2C: Class-expansion — memory & concurrency (v0.2)

Dispatch in parallel:
- `thread-safety-auditor` (Class F — non-Sync interior mutability on a shared `#[pyclass]` payload)
- `debug-format-auditor` (Class I — `{:?}` on a Python object; severity-gated on the unsound `PyAtomicRef` Debug)
- `capi-panic-boundary` (panics + unguarded pointer derefs across the C ABI in `crates/capi`; **experimental, 0 fuzzer-confirmed**)

### Phase 2D: Class-expansion — reachability & parity (v0.2)

Dispatch in parallel:
- `ctypes-ffi-auditor` (Class H — int→pointer narrowing in `_ctypes`)
- `recursion-guard-auditor` (Class D — unguarded recursion in a protocol slot)
- `eager-collect-parity` (Class G — eager iterable binding where CPython streams; **lowest-precision, needs a CPython differential**)
- `uninitialized-object-auditor` (Class E — a payload slot on a `T.__new__(T)` instance)

### Phase 2E: Quality and history

Dispatch in parallel:
- `rust-complexity-analyzer`
- `git-history-analyzer` (runs after the others so it can overlay their findings on churn)

### Phase 3: Synthesis

Aggregate every agent's report. Deduplicate findings surfaced by multiple agents (same file:line). Produce a unified summary at `reports/<target>_v1/SUMMARY.md`:

1. **Top FIX findings** across all agents (panic-site FIX + unsafe-soundness FIX + ctypes int-narrow FIX first).
2. **Per-crate breakdown** of FIX / CONSIDER / POLICY / ACCEPTABLE counts.
3. **Per-agent links** to the detailed reports.
4. **The experimental caveats**: gc-traverse and capi-panic-boundary have 0 fuzzer-confirmed instances; thread-safety needs a concurrency differential; eager-collect and uninit need a CPython differential — none of these reach FIX on static evidence alone.
5. **The debug-format severity gate** (is the unsound `PyAtomicRef` Debug still live?) and any **calibration notes** observed across the run.

## Output

All findings go to `reports/<target>_v1/`. Summary at the top; per-agent reports in `agents/`; preflight in `preflight/`.

For maintainer-facing output (sharing back to RustPython upstream), follow `docs/writing-maintainer-facing-reports.md` and `WORKING_WITH_MAINTAINERS.md`. RustPython's object model is under active upstream churn — pin every `file:line` citation to the reviewed commit.
