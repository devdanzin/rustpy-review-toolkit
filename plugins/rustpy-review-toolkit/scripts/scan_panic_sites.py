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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import classify_functions, load_protocol_traits  # noqa: E402
from rust_ts_utils import parse_bytes  # noqa: E402
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
                    classification, confidence = _classify(
                        tier, pattern, high, has_weak
                    )
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
