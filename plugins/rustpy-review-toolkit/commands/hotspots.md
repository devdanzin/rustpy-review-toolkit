---
description: "Find the worst functions in the RustPython interpreter. Use when the user asks where to focus review effort — runs the panic-site, unsafe-soundness, and complexity agents and ranks the riskiest code by combined risk."
argument-hint: "[scope]"
allowed-tools: ["Bash", "Glob", "Grep", "Read", "Task"]
---

# RustPython Internals Hotspots

Answer one question: **where should review effort go first?** This runs the agents whose findings concentrate in specific functions, then ranks those functions by combined risk.

**Arguments:** "$ARGUMENTS"  (scope only — path or glob; default `.`)

**Plugin root:** `<plugin_root>` is the `plugins/rustpy-review-toolkit/` directory.

## Why these agents

RustPython's danger concentrates in Python-reachable panic sites and the raw-pointer object model — **not** in reference counting (the `RefCount` is all-safe atomics) or GIL discipline (there is no GIL to mismanage the way a C extension does). So hotspots runs:

- **panic-site-auditor** — Python-triggerable interpreter aborts (the flagship class)
- **unsafe-soundness-auditor** — the object-model cast-inconsistency / handle-transmute class
- **rust-complexity-analyzer** — the functions hardest to review

(This mix reflects RustPython's real bug surface, not a transplant of a PyO3 or C-extension checklist.)

## Workflow

1. **Discovery** — `python <plugin_root>/scripts/discover_rustpy.py [scope]`; print the profile. Stop if `is_rustpython` is false or `out_of_scope` is true.
2. **Preflight** — dispatch `rustpy-internals-mapper` (the reachability tiers are load-bearing for ranking panics).
3. **Dispatch** the three agents above against the scope.
4. **Rank.** Group all findings by function (`qualified_name` / `function`). A function's risk score:
   - **+3** per FIX finding, **+1** per CONSIDER finding.
   - **+2** if `rust-complexity-analyzer` flagged it a `complex_function`.
   - **×1.5** if the function carries BOTH an unsafe-soundness finding *and* a complexity flag — a complex `unsafe` function in the object model is the single most dangerous shape in the interpreter.
   - **+1** if the panic site is `py`-tier (directly Python-callable) rather than `protocol`-tier.

## Output

```markdown
# Hotspots — RustPython

version [N] | scope: [path]

| Rank | Function | File:Line | Risk | FIX | CONSIDER | Why |
|------|----------|-----------|------|-----|----------|-----|
| 1 | [name] | [file:line] | 9.0 | 2 | 1 | complex + unsafe cast inconsistency |
| ... | | | | | | |

## Top 5 — act on these first
[For each: the one-line reason and the concrete fix.]

## Recommended next step
[Point at "/rustpy-review-toolkit:explore" on the hottest crate, or "/rustpy-review-toolkit:known-issues" to check whether any hotspot is a fuzzer-confirmed crash.]
```

Keep it focused. This command ranks; `/rustpy-review-toolkit:explore` audits.
