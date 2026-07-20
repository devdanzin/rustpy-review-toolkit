---
description: "Quick scored health dashboard for the RustPython interpreter's own source. Use when the user wants a fast overall-quality read rather than a full review — runs every agent in summary mode and scores each dimension 1-10."
argument-hint: "[scope]"
allowed-tools: ["Bash", "Glob", "Grep", "Read", "Task"]
---

# RustPython Internals Health Dashboard

Produce a quick, scored health read of RustPython's own source. Every agent runs in **summary mode** — enough to score each dimension, not a full finding-by-finding audit.

**Arguments:** "$ARGUMENTS"  (scope only — path or glob; default `.`)

**Plugin root:** `<plugin_root>` is the `plugins/rustpy-review-toolkit/` directory.

## Workflow

1. **Discovery** — `python <plugin_root>/scripts/discover_rustpy.py [scope]`; print the one-line profile. Stop if `is_rustpython` is false or `out_of_scope` is true.
2. **Preflight** — dispatch `rustpy-internals-mapper` (fast; every agent benefits from the reachability tiers).
3. **Dimensions** — dispatch each agent in summary mode. Each runs its scanner and reports only counts (FIX / CONSIDER / POLICY) and the single worst finding.

| Dimension | Agent |
|-----------|-------|
| Python-reachable panics | panic-site-auditor |
| Unsafe soundness | unsafe-soundness-auditor |
| GC traverse-completeness | gc-traverse-auditor |
| Complexity | rust-complexity-analyzer |
| History / churn | git-history-analyzer |

## Scoring

Each dimension is scored **1–10**, starting at 10:

- **−3 per FIX finding** (a Python-triggerable crash / a memory-unsafety cast).
- **−1 per CONSIDER finding**, capped at −4 total.
- **−0 for POLICY / ACCEPTABLE**.
- Floor at 1.

**gc-traverse never emits FIX** (experimental) — score it on CONSIDER volume only, and note the experimental caveat.

Map to a letter: **9–10 = A**, **7–8 = B**, **5–6 = C**, **3–4 = D**, **1–2 = F**.

## Output

```markdown
# Health Dashboard — RustPython

version [N] | in-scope crates: [...] | threading: [on/off] | shallow clone: [yes/no]

| Dimension | Score | Grade | FIX | CONSIDER | Worst Finding |
|-----------|-------|-------|-----|----------|---------------|
| Python-reachable panics | 6/10 | C | 2 | 5 | [1-line] |
| ... | | | | | |

**Overall: [average]/10 — [grade]**

## Headline
[2–3 sentences: the single most important thing to fix (usually a py/protocol-tier panic), and the interpreter's overall state.]

## Recommended next step
[Either "/rustpy-review-toolkit:explore . <aspects>" for the weakest dimensions, "/rustpy-review-toolkit:hotspots" if panics + complexity both scored low, or "/rustpy-review-toolkit:known-issues" to check the fuzzer-confirmed catalog.]
```

Keep it to one screen. For a finding-by-finding audit, point the user at `/rustpy-review-toolkit:explore`.
