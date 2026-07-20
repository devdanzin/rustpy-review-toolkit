#!/usr/bin/env python3
"""Flagship scanner: Python-reachable panic sites in the RustPython VM.

RustPython's dominant crash class is a native ``.unwrap()`` / ``.expect()`` /
``panic!`` / unchecked index reached from a Python program (12 of the 24
confirmed fuzzer findings). Unlike a soundness bug, a panic here doesn't corrupt
memory — it aborts the interpreter (or unwinds), turning any Python call into a
denial-of-service. This scanner finds every such site and **ranks it by
reachability tier**, so the ones a Python program can actually trigger surface
while the interpreter's internal invariants stay quiet.

The classification (which fn is `py` / `protocol` / `internal`) comes from
``map_rustpy_internals.classify_functions`` — the single source of truth. This
scanner overlays two things on top:

1. **Tier gating.** Panics in `internal`-tier helpers are DEFAULT-SILENCED
   (counted, not emitted) — they are not directly Python-triggerable, and
   emitting them drowns the signal. Pass ``--include-internal`` to surface them.
2. **Reachability ranking.** For each `py`/`protocol` site, the failing value's
   provenance is scored against ``rustpython_reachability_sources.json`` — a
   panic on a value that flows from a Python argument / a downcast / an int
   narrowing / a user index is a real remotely-triggerable crash (FIX); one on a
   VM-established invariant is weaker (CONSIDER).

Port of the fuzzing seed tool ``unwrap_scan`` (rustpython-findings) to
Python + tree-sitter, plus the reachability ranking the seed did not have.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import classify_functions, load_protocol_traits  # noqa: E402
from rust_ts_utils import parse_bytes, strip_comments  # noqa: E402
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    load_data_file,
    make_finding,
    parse_common_args,
    relative_path,
)

# Risky patterns (substring match on non-comment lines). Ported from the
# fuzzing seed tool's PATTERNS. ``args-index`` catches arity OOB (the
# `_typing._idfunc` face: indexing `args[N]` without checking arity).
PATTERNS: tuple[tuple[str, str], ...] = (
    (".unwrap()", "unwrap"),
    (".expect(", "expect"),
    ("panic!", "panic"),
    ("unreachable!", "unreachable"),
    ("unimplemented!", "unimplemented"),
    ("todo!", "todo"),
    (".args[", "args-index"),
)

# Patterns that panic on a *fallible value* (as opposed to an explicit abort
# macro). These are the ones the reachability ranking is meaningful for.
_FALLIBLE_VALUE_PATTERNS = frozenset({"unwrap", "expect", "args-index"})

# A length/arity guard in the enclosing context — an `if (2..=5).contains(&len)`,
# a `match args.len()` arm, an `if len == 2`, etc. When a fallible-value panic
# (typically `args[N]` / `get_arg(N)`) sits inside one, the index is bounded and
# the site is very likely a false positive; it is down-ranked to CONSIDER. An
# UNGUARDED arity index (the `_typing._idfunc` shape, RUSTPY-0005) has no such
# guard and stays FIX. Calibration from the exceptions.rs deep-dive, where all
# 14 scanner-FIX arity indices were guarded false positives.
_LENGTH_GUARD_RE = re.compile(
    r"\.len\(\)\s*(?:==|!=|>=|<=|>|<)"  # x.len() == N
    r"|(?:==|!=|>=|<=|>|<)\s*[\w.]*\.?len\(\)"  # N <= x.len()
    r"|(?:==|>=|<=|>|<)\s*len\b"  # >= len
    r"|\blen\s*(?:==|>=|<=|>|<)"  # len >= N
    r"|match\s+[\w.]+\.len\(\)"  # match x.len()
    r"|\.contains\(&?\s*\w*len"  # (N..=M).contains(&len)
)
# How far back to look for the guard (covers a match arm / if-block header,
# including guards a nested block pushes ~14 lines above the index).
_GUARD_LOOKBACK = 16

# A function body that is nothing but a single `unreachable!(...)` /
# `unimplemented!(...)` macro is a deliberate "this is not the live impl" marker
# — in RustPython these shadow a sibling `slot_*` form (`unreachable!("slot_init
# is defined")`, `unimplemented!("use slot_new")`). The panic in such a stub is
# not a data-dependent crash, so it is classified ACCEPTABLE rather than
# surfaced. `todo!` is deliberately NOT included — a `todo!()` body is genuinely
# unimplemented work worth a CONSIDER. Calibration from the exceptions.rs
# meta-eval (10+ shadowed `unreachable!` init stubs).
_STUB_BODY_RE = re.compile(
    r"^(?:unreachable|unimplemented)!\s*\(.*?\)\s*;?$", re.DOTALL
)


def _is_pure_abort_stub(body_node: object, source: bytes) -> bool:
    """True if a fn body is nothing but one `unreachable!`/`unimplemented!`."""
    inner = (
        strip_comments(
            source[body_node.start_byte : body_node.end_byte]  # type: ignore[attr-defined]
        )
        .decode("utf-8", "replace")
        .strip()
    )
    if inner.startswith("{"):
        inner = inner[1:]
    if inner.endswith("}"):
        inner = inner[:-1]
    return bool(_STUB_BODY_RE.match(inner.strip()))


def _load_reachability() -> tuple[list[dict], list[str]]:
    """Return (categories, weak_internal_tokens) from the data file."""
    data = load_data_file("rustpython_reachability_sources.json")
    cats = data.get("categories", []) if isinstance(data, dict) else []
    weak_block = data.get("weak_internal_signals", {}) if isinstance(data, dict) else {}
    weak = weak_block.get("tokens", []) if isinstance(weak_block, dict) else []
    return (cats if isinstance(cats, list) else []), (
        weak if isinstance(weak, list) else []
    )


def _reachability_signals(
    window_text: str, cats: list[dict], weak: list[str]
) -> tuple[list[str], bool, bool]:
    """Score a candidate's context window against the reachability sources.

    Returns (matched_category_names, has_high_weight_signal, has_weak_signal).
    """
    matched: list[str] = []
    high = False
    for c in cats:
        tokens = c.get("tokens", []) if isinstance(c, dict) else []
        if any(str(t) in window_text for t in tokens):
            matched.append(str(c.get("name", "")))
            if c.get("weight") == "high":
                high = True
    has_weak = any(str(t) in window_text for t in weak)
    return matched, high, has_weak


def _classify(tier: str, pattern: str, high: bool, has_weak: bool) -> tuple[str, str]:
    """Map (tier, pattern, signals) → (classification, confidence).

    Calibration (design §6):
      * internal tier → ACCEPTABLE (silenced unless --include-internal)
      * py/protocol + fallible-value pattern + high Python-controlled signal
        and no weak-invariant signal → FIX (a Python program can abort the VM)
      * py/protocol + fallible-value pattern otherwise → CONSIDER
      * py/protocol + explicit abort macro (panic!/unreachable!/todo!) →
        CONSIDER (often a deliberate "can't happen"; the agent verifies whether
        a Python path reaches it)
    """
    if tier == "internal":
        return "ACCEPTABLE", "LOW"
    if pattern in _FALLIBLE_VALUE_PATTERNS:
        if high and not has_weak:
            return "FIX", "HIGH"
        if has_weak:
            return "CONSIDER", "LOW"
        return "CONSIDER", "MEDIUM"
    # Explicit abort macros: reachable, but usually intentional.
    return ("CONSIDER", "MEDIUM") if high else ("CONSIDER", "LOW")


def analyze(target: str, *, max_files: int = 0, include_internal: bool = False) -> dict:
    """Scan RustPython at ``target`` for Python-reachable panic sites."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    protocol_traits = load_protocol_traits()
    cats, weak = _load_reachability()

    findings: list[dict] = []
    internal_suppressed = 0
    total_fns = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        default_module = path.parent.name
        rel = relative_path(path, project_root)
        lines = source.decode("utf-8", "replace").splitlines()

        for fn in classify_functions(
            tree, source, default_module, protocol_traits=protocol_traits
        ):
            total_fns += 1
            body = fn["body_node"]
            if body is None:
                continue
            tier = fn["reachable"]
            is_stub = _is_pure_abort_stub(body, source)
            b_start = body.start_point[0] + 1
            b_end = body.end_point[0] + 1
            for ln in range(b_start, min(b_end, len(lines)) + 1):
                raw = lines[ln - 1]
                if raw.lstrip().startswith("//"):
                    continue
                for needle, pattern in PATTERNS:
                    if needle not in raw:
                        continue
                    if tier == "internal" and not include_internal:
                        internal_suppressed += 1
                        continue
                    window = "\n".join(lines[max(0, ln - 4) : ln])
                    matched, high, has_weak = _reachability_signals(window, cats, weak)
                    # A fallible-value panic inside a length/arity guard is very
                    # likely a bounded false positive → down-rank like a weak
                    # signal. An unguarded arity index stays FIX.
                    guarded = pattern in _FALLIBLE_VALUE_PATTERNS and bool(
                        _LENGTH_GUARD_RE.search(
                            "\n".join(lines[max(0, ln - _GUARD_LOOKBACK) : ln])
                        )
                    )
                    classification, confidence = _classify(
                        tier, pattern, high, has_weak or guarded
                    )
                    # A pure abort-macro stub body is a deliberate shadow marker,
                    # not a data crash → ACCEPTABLE.
                    if is_stub and pattern in ("unreachable", "unimplemented"):
                        classification, confidence = "ACCEPTABLE", "LOW"
                    snippet = raw.strip()[:100]
                    findings.append(
                        make_finding(
                            "panic_site",
                            classification=classification,
                            confidence=confidence,
                            description=(
                                f"{pattern} in {tier}-reachable {fn['kind']} "
                                f"{fn['qualified_name']} (module {fn['module']}): {snippet}"
                            ),
                            file=rel,
                            line=ln,
                            function=fn["qualified_name"],
                            category=tier,
                            details={
                                "pattern": pattern,
                                "tier": tier,
                                "kind": fn["kind"],
                                "python_name": fn["python_name"],
                                "class": fn["class"],
                                "module": fn["module"],
                                "trait": fn["trait"],
                                "reachability_signals": matched,
                                "high_reachability": high,
                                "weak_invariant_signal": has_weak,
                                "length_guarded": guarded,
                                "stub_body": is_stub,
                            },
                        )
                    )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(discovery, findings, functions_analyzed=total_fns)
    report["panic_scan"] = {
        "internal_sites_suppressed": internal_suppressed,
        "include_internal": include_internal,
        "patterns": [p for _, p in PATTERNS],
    }
    return report


def main() -> None:
    try:
        argv = sys.argv[1:]
        include_internal = "--include-internal" in argv
        argv = [a for a in argv if a != "--include-internal"]
        target, max_files = parse_common_args(argv)
        result = analyze(target, max_files=max_files, include_internal=include_internal)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except Exception as e:  # noqa: BLE001 -- top-level guard, emit JSON error
        json.dump({"error": str(e), "type": type(e).__name__}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
