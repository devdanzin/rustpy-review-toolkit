#!/usr/bin/env python3
"""recursion-guard-auditor — Class D: unguarded recursion in a protocol slot.

A protocol op (hash, richcompare, str, `__reduce__`, genericalias parameter walk)
that recurses in Rust following a Python object graph with **no recursion depth
guard** overflows the *native* stack on a deep/cyclic object → SIGSEGV, not a
catchable `RecursionError`. RustPython guards `__repr__` per-object with
`ReprGuard` (`recursion.rs:13`) and frame depth with `with_recursion`
(`vm/mod.rs:1681`), but `__str__`/`__eq__`/`__hash__` on the same containers
recurse element-wise with no per-slot guard. That asymmetry is the finding.

Signal: a `protocol`-tier method (from the mapper) whose body recurses into an
element (calls `.repr(vm)`/`.str(vm)`/`.hash(vm)`/`.rich_compare(...)` etc.) but
contains **no** guard call (`ReprGuard::enter`/`with_recursion`/...).

**Calibration: CONSIDER** — a known-open upstream umbrella (#2796); per-area
fixes have landed (json/AST/parser). Whether a given slot is reachable with a
deep-enough or cyclic object is human judgment (standard recursion tests pass —
the triggers are specific object graphs). Framed like gc-traverse.
"""

import json
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

_DEFAULT_GUARDS = (
    "ReprGuard",
    "with_recursion",
    "enter_recursive_call",
    "check_recursive_call",
    "check_c_stack_overflow",
)
_DEFAULT_RECURSION = (
    ".repr(vm",
    ".str(vm",
    ".hash(vm",
    "._hash(vm",
    ".rich_compare(",
    ".reduce(vm",
    "make_parameters",
)
# The protocol slots where unguarded recursion overflows the native stack.
_RECURSION_SLOTS = {
    "__repr__",
    "__str__",
    "__hash__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__reduce__",
    "__reduce_ex__",
}
_RECURSION_TRAITS = {"Representable", "Hashable", "Comparable"}
# Deep recursion requires iterating a *collection* of Python objects — a slot
# that touches a fixed number of fields (bytes hashing its buffer, a bound
# method hashing `(func, object)`) cannot recurse arbitrarily deep. Requiring an
# iteration/collection token alongside the recursion call cuts the scalar shapes.
_ITER_TOKENS = (
    ".iter(",
    "for ",
    ".map(",
    ".args",
    ".elements",
    ".items(",
    ".values(",
    ".keys(",
    ".into_iter(",
    ".parameters",
    "make_parameters",
)


def _load_tokens() -> tuple[list[str], list[str]]:
    data = load_data_file("recursion_guard_tokens.json")
    guards = data.get("guard_tokens") if isinstance(data, dict) else None
    recur = data.get("recursion_tokens") if isinstance(data, dict) else None
    return (
        [str(t) for t in guards]
        if isinstance(guards, list) and guards
        else list(_DEFAULT_GUARDS),
        [str(t) for t in recur]
        if isinstance(recur, list) and recur
        else list(_DEFAULT_RECURSION),
    )


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan RustPython for protocol slots that recurse without a guard."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    protocol_traits = load_protocol_traits()
    guard_tokens, recursion_tokens = _load_tokens()

    findings: list[dict] = []
    slots_analyzed = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        rel = relative_path(path, project_root)
        default_module = path.parent.name
        stripped = strip_comments(source).decode("utf-8", "replace").splitlines()

        for fn in classify_functions(
            tree, source, default_module, protocol_traits=protocol_traits
        ):
            if fn["reachable"] != "protocol":
                continue
            slot = fn["python_name"] in _RECURSION_SLOTS
            trait_hit = fn["trait"] in _RECURSION_TRAITS
            if not slot and not trait_hit:
                continue
            body = fn["body_node"]
            if body is None:
                continue
            slots_analyzed += 1
            b_start = body.start_point[0] + 1
            b_end = body.end_point[0] + 1
            body_text = "\n".join(stripped[b_start - 1 : b_end])

            recurses = [t for t in recursion_tokens if t in body_text]
            if not recurses:
                continue
            if not any(it in body_text for it in _ITER_TOKENS):
                continue  # not iterating a collection → not deep-recursion-prone
            if any(g in body_text for g in guard_tokens):
                continue  # guarded (the ReprGuard-protected repr slots)

            findings.append(
                make_finding(
                    "unguarded_protocol_recursion",
                    classification="CONSIDER",
                    confidence="MEDIUM",
                    description=(
                        f"`{fn['qualified_name']}` (Python "
                        f"`{fn['python_name'] or fn['trait']}`) recurses into a "
                        f"contained object ({', '.join(recurses)}) with no recursion "
                        f"guard (`ReprGuard::enter` / `with_recursion`). A deep or "
                        f"cyclic object overflows the native stack → SIGSEGV (not a "
                        f"catchable RecursionError). The `__repr__` slot on the same "
                        f"type is guarded; this one is not."
                    ),
                    file=rel,
                    line=fn["start_line"],
                    function=fn["qualified_name"],
                    category="recursion-guard",
                    details={
                        "python_name": fn["python_name"],
                        "trait": fn["trait"],
                        "class": fn["class"],
                        "recursion_calls": recurses,
                        "check": "unguarded_protocol_recursion",
                    },
                )
            )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(discovery, findings, functions_analyzed=slots_analyzed)
    report["recursion_scan"] = {
        "note": (
            "CONSIDER — known-open upstream umbrella #2796; a native stack "
            "overflow is a SIGSEGV, not a catchable RecursionError. Guarded "
            "json/AST/parser paths are the SAFE set."
        )
    }
    return report


def main() -> None:
    try:
        target, max_files = parse_common_args(sys.argv[1:])
        result = analyze(target, max_files=max_files)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except Exception as e:  # noqa: BLE001 -- top-level guard, emit JSON error
        json.dump({"error": str(e), "type": type(e).__name__}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
