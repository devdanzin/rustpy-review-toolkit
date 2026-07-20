#!/usr/bin/env python3
"""eager-collect-parity — Class G: unbounded eager collection where CPython streams.

A `#[pyfunction]`/`#[pymethod]`/`Constructor` argument typed `Vec<PyObjectRef>` /
`ArgIterable<_>` that **collects the whole Python argument up front** with no
length/type check, where CPython at the same position requires a *sized
container* and raises `TypeError`/`ValueError` **before** consuming. An
infinite/huge iterable (`itertools.count()`, a lying `__getitem__`) balloons
RustPython → OOM abort; CPython rejects in O(1).

**The wall (honest framing).** Locating an eager collection is easy; *proving the
parity gap* is not. The Python-name → helper-fn chain is opaque through
`atomic_func!` slot dispatch + the `PySequenceMethods`/`PyMappingMethods` vtable
(the v0.1 call-graph wall). So this is **site-enumeration + the fuzzer's verified
SAFE list + a human differential** (CONSIDER only), not automatic parity proof.
The parity gap is *exactly* the 5 findings 0012–0016; the general `ArgIterable`
mechanism is not itself a new source once CPython's type-checking is accounted
for. **Class J (abort-vs-MemoryError, both interpreters balloon) is OUT OF SCOPE.**
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import classify_functions, load_protocol_traits  # noqa: E402
from rust_ts_utils import extract_fn_items, parse_bytes, text_of  # noqa: E402
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    load_data_file,
    make_finding,
    parse_common_args,
    relative_path,
)

_DEFAULT_LAZY = ("Vec<PyIter", "PyIter>", "Either<", "ArgMapping")
_DEFAULT_VARARGS = ("args", "_args", "kwargs", "_kwargs")

# An eagerly-bound Python iterable PARAMETER: FromArgs materializes the whole
# argument into a Vec / ArgIterable BEFORE the body runs. `ArgIterable<_>` is
# always eager; `Vec<PyObjectRef>` / `Vec<PyRef<_>>` is eager unless it is the
# `*args` varargs (a bounded, finite call).
_EAGER_PARAM_RE = re.compile(
    r"\bArgIterable\s*<|\bVec\s*<\s*PyObjectRef\b|\bVec\s*<\s*PyRef\s*<"
)
_ARGITERABLE_RE = re.compile(r"\bArgIterable\s*<")
# Split a params list into `name: type` pairs (rough — good enough for the type).
_PARAM_RE = re.compile(r"(?:#\[[^\]]*\]\s*)?(\w+)\s*:\s*([^,]+(?:<[^>]*>)?[^,]*)")


def _load_lists() -> dict:
    data = load_data_file("eager_collect_safe_list.json")
    return data if isinstance(data, dict) else {}


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Flag py/protocol functions with an eagerly-bound iterable parameter."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    protocol_traits = load_protocol_traits()
    lists = _load_lists()

    lazy_tokens = lists.get("lazy_safe_tokens") or list(_DEFAULT_LAZY)
    varargs_names = set(lists.get("varargs_param_names") or _DEFAULT_VARARGS)
    safe_fns = {str(t) for t in lists.get("safe_function_names", [])}
    gap_fn_names = {
        str(g.get("function", "")): g
        for g in lists.get("known_parity_gap_functions", [])
    }

    findings: list[dict] = []
    fns_seen = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        rel = relative_path(path, project_root)
        default_module = path.parent.name

        # Tier per fn start line (the mapper is the source of truth).
        tier_by_line = {
            fn["start_line"]: fn
            for fn in classify_functions(
                tree, source, default_module, protocol_traits=protocol_traits
            )
        }

        for item in extract_fn_items(tree, source):
            info = tier_by_line.get(item["start_line"])
            if info is None or info["reachable"] == "internal":
                continue  # only Python-exposed positions take a hostile iterable
            if item["params_node"] is None:
                continue
            params_text = text_of(item["params_node"], source)
            fns_seen += 1

            eager_params: list[tuple[str, str]] = []
            for pname, ptype in _PARAM_RE.findall(params_text):
                if any(t in ptype for t in lazy_tokens):
                    continue  # lazy Vec<PyIter> / Either / ArgMapping
                if not _EAGER_PARAM_RE.search(ptype):
                    continue
                # A bare `Vec<PyObjectRef>` named `args` is bounded varargs; an
                # `ArgIterable` is eager even when named `args` (posix execv).
                if pname in varargs_names and not _ARGITERABLE_RE.search(ptype):
                    continue
                eager_params.append((pname, ptype.strip()))
            if not eager_params:
                continue

            fn_name = info["rust_name"] or ""
            py_name = info["python_name"] or ""
            if fn_name in safe_fns or py_name in safe_fns:
                continue  # verified-SAFE (lazy short-circuit / Class J / bounded)

            gap = gap_fn_names.get(fn_name)
            pdesc = ", ".join(f"`{n}: {t}`" for (n, t) in eager_params)
            findings.append(
                make_finding(
                    "eager_collect_parity",
                    classification="CONSIDER",
                    confidence="HIGH" if gap else "LOW",
                    description=(
                        f"`{info['qualified_name']}` binds a Python iterable "
                        f"eagerly via parameter(s) {pdesc} — FromArgs materializes "
                        f"the whole argument into a Vec before the body runs. If "
                        f"CPython requires a sized container here and rejects an "
                        f"infinite/huge iterable in O(1), RustPython balloons → OOM. "
                        + (
                            f"Fuzzer-confirmed parity gap {gap.get('id')}."
                            if gap
                            else "Confirm against CPython's signature (many positions "
                            "are safe — see the SAFE list)."
                        )
                    ),
                    file=rel,
                    line=item["start_line"],
                    function=info["qualified_name"],
                    category="eager-collect",
                    details={
                        "tier": info["reachable"],
                        "python_name": py_name,
                        "eager_params": [n for (n, _) in eager_params],
                        "known_parity_gap": gap.get("id") if gap else None,
                        "check": "eager_collect_parity",
                    },
                )
            )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(discovery, findings, functions_analyzed=fns_seen)
    report["eager_collect_scan"] = {
        "note": (
            "CONSIDER — site-enumeration + SAFE-list + human differential; the "
            "Python-name->helper parity chain is opaque through atomic_func!. "
            "Class J (abort-vs-MemoryError) is out of scope. Confirmed gaps are "
            "exactly 0012-0016."
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
