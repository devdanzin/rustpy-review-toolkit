---
description: "Cross-reference the confirmed-crash catalog (fusil fuzzing RUSTPY-* + this toolkit's reproduced static-review findings RPYR-*) against a fresh scan of RustPython. Reports which reproduced interpreter crashes are still present, drifted, or fixed. The toolkit's signature regression command — static, drift-tolerant, no repros run."
argument-hint: "[scope]"
allowed-tools: ["Bash", "Glob", "Grep", "Read", "Task"]
---

# RustPython Known-Issues Regression

The signature command of this toolkit. `data/known_panics.tsv` records crash sites confirmed as **reproduced interpreter crashes** from two sources — the `fusil` + CPython-differential fuzzing campaign (`RUSTPY-NNNN`) and this toolkit's static review, then reproduced (`RPYR-NNNN`) — each a `crates/…:line` signature. This command runs a fresh panic-site scan and reports, per confirmed bug, whether it is still in the tree. (Some recursion/segv sites carry no panic token — e.g. RPYR-0013/0014 hash recursion — so they read `absent` against a panic scan though unfixed; read the file to confirm.)

It is **static and drift-tolerant** — it does not run the repros. It answers: "of the crashes we know a Python program can trigger, which are still unfixed at this checkout?"

**Arguments:** "$ARGUMENTS"  (scope only — path or glob; default the whole workspace).

**Plugin root:** `<plugin_root>` is the `plugins/rustpy-review-toolkit/` directory.

## Workflow

1. **Discovery** — `python <plugin_root>/scripts/discover_rustpy.py [scope]`; confirm `is_rustpython`. Record the reviewed commit (`git -C <project_root> rev-parse --short HEAD`) — the catalog was captured at a slightly different commit, so line drift is expected.

2. **Cross-reference:**
   ```
   python <plugin_root>/scripts/check_known_issues.py [scope]
   ```
   The `known_issues` block reports, per catalog site, one of:
   - **`present`** — a panic finding at exactly that file:line (still unfixed).
   - **`line_drifted`** — the file still has panic sites but not at that exact line; `nearest_panic_line` points at the closest one. The bug is very likely still there, a few lines moved.
   - **`absent`** — the file has no panic sites (likely fixed or refactored away).
   - **`file_missing`** — the file no longer exists.

   The `bug_rollup` collapses a bug's sites into one verdict (`present` / `line_drifted` / `likely_fixed`).

3. **Verify the drifted and absent ones.** For each `line_drifted` bug, Read the file around `nearest_panic_line` and confirm the same panic shape is present (the reachability tier + pattern should match the catalog). For each `absent`/`likely_fixed` bug, Read the file to confirm the panic really is gone (not just moved to another file) — a genuine fix is worth noting.

## Output

```markdown
# Known-Issues Regression — RustPython @ [commit]

Catalog: [N] confirmed bugs, [M] sites. Reviewed at [commit] (catalog captured at a9c2c529b).

| Bug | Verdict | Site(s) | Notes |
|-----|---------|---------|-------|
| RUSTPY-0018 | present | object/ext.rs:277 | PyAtomicRef Debug SIGSEGV — still one char from fixed |
| RUSTPY-0009 | present | staticmethod.rs:182 | Representable repr unwrap |
| ... | | | |

**Still present: [n] / [total]**   **Likely fixed: [k]**

## Confirmed-still-unfixed (act on these)
[List the `present` bugs with the one-line fix each needs.]

## Likely fixed since the campaign
[List the `absent` bugs — verify and celebrate.]
```

Note: a `present` verdict means a fuzzer-**reproduced** crash is still in the tree — the highest-confidence findings this toolkit produces. Treat them as FIX. When sharing upstream, follow `WORKING_WITH_MAINTAINERS.md` and cite the `RUSTPY-NNNN` id and the repro filename (`repros/RUSTPY-NNNN_*.py` in the findings repo, if available).
