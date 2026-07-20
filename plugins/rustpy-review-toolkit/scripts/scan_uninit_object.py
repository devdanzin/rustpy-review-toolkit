#!/usr/bin/env python3
"""uninitialized-object-auditor — Class E: a slot on a `T.__new__(T)` instance.

Most native types have no own `Constructor`/`DISALLOW_INSTANTIATION`, so
`T.__new__(T)` yields a type-confused instance with a default (`PyBaseObject`)
payload. The type's `#[pymethod]`s cleanly `downcast`-fail (TypeError), but a
**protocol slot** (`AsMapping`/`AsSequence`/`AsNumber`/iterator) that touches the
payload via an unchecked `*_downcast` reads garbage → SIGSEGV.

Signal (heuristic): a `#[pyclass]` payload T that
  1. has a protocol-slot impl (`impl AsMapping/AsSequence/AsNumber/IterNext for T`)
     — these access the payload — AND
  2. has **no** `Constructor`/`Unconstructible`/`DefaultConstructor` /
     `DISALLOW_INSTANTIATION` forbidding `T.__new__(T)`.

**Honest framing — the toolkit's most heuristic check (CONSIDER only).** Even the
fuzzer's own 0008 (`_sre` `Match::as_mapping`) is really a slot-payload-invariant
OOB (`regs[index]` with `<=`), not a clean uninit. Whether an uninitialized
instance actually reaches a payload read without a re-check is dataflow the
scanner does not prove — it enumerates the *shape* and the agent verifies.
Cross-linked from the unsafe-soundness agent's `assume_init` note.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import _bare_ident, extract_pyclass_payloads  # noqa: E402
from rust_ts_utils import (  # noqa: E402
    extract_attributes,
    extract_impl_blocks,
    parse_bytes,
    text_of,
)
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    make_finding,
    parse_common_args,
    relative_path,
)

# Protocol slots that touch the payload (the uninit-reachable surface).
_PAYLOAD_SLOT_TRAITS = {"AsMapping", "AsSequence", "AsNumber", "IterNext", "AsBuffer"}
# Traits / markers that forbid or define `__new__` (so `T.__new__(T)` is safe).
_CTOR_TRAITS = {"Constructor", "Unconstructible", "DefaultConstructor"}
# Markers inside a `#[pyclass(...)]` attribute that forbid/define `__new__`.
_CTOR_ATTR_MARKERS = (
    "Constructor",
    "Unconstructible",
    "DefaultConstructor",
    "DISALLOW_INSTANTIATION",
)
# Unchecked payload-downcast idioms a slot uses on its receiver.
_UNCHECKED_TOKENS = (
    "_downcast(",
    "downcast_unchecked",
    "payload_unchecked",
    "payload::<",
)


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Flag pyclass payloads with a payload slot but no constructor guard."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)

    findings: list[dict] = []
    payloads_analyzed = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        rel = relative_path(path, project_root)
        default_module = path.parent.name

        impls = extract_impl_blocks(tree, source)
        slot_types: dict[str, list[str]] = {}
        ctor_types: set[str] = set()
        unchecked_slot_types: set[str] = set()
        for ib in impls:
            typ = _bare_ident(ib["type"])
            trait = _bare_ident(ib["trait"]) if ib["trait"] else ""
            # A `#[pyclass(with(Constructor, ...))]` / DISALLOW_INSTANTIATION on
            # the impl block defines/forbids __new__ (precise, per-type).
            for attr in extract_attributes(ib["node"], source):
                if attr.get("name") == "pyclass" and any(
                    mk in (attr.get("args_text") or "") for mk in _CTOR_ATTR_MARKERS
                ):
                    ctor_types.add(typ)
            if not trait:
                continue
            if trait in _PAYLOAD_SLOT_TRAITS:
                slot_types.setdefault(typ, []).append(trait)
                body = ib["body_node"]
                if body is not None and any(
                    t in text_of(body, source) for t in _UNCHECKED_TOKENS
                ):
                    unchecked_slot_types.add(typ)
            if trait in _CTOR_TRAITS:
                ctor_types.add(typ)

        payloads = extract_pyclass_payloads(tree, source, default_module)
        for p in payloads:
            name = p["rust_name"]
            if not p["fields"]:
                continue  # no payload state to misread
            if name not in slot_types:
                continue
            payloads_analyzed += 1
            if name in ctor_types:
                continue  # defines/forbids __new__ → T.__new__(T) is guarded

            unchecked = name in unchecked_slot_types
            findings.append(
                make_finding(
                    "uninitialized_object_slot",
                    classification="CONSIDER",
                    confidence="MEDIUM" if unchecked else "LOW",
                    description=(
                        f"`{name}` (Python `{p['python_name']}`) exposes protocol "
                        f"slot(s) {', '.join(sorted(set(slot_types[name])))} that "
                        f"touch its payload, but has no `Constructor`/"
                        f"`Unconstructible`/`DISALLOW_INSTANTIATION` forbidding "
                        f"`{p['python_name']}.__new__(...)`. A type-confused "
                        f"`__new__` instance carries a default payload; if the slot "
                        f"reads it without re-downcasting it reads garbage "
                        f"(SIGSEGV, the _sre Match::as_mapping class)."
                        + (
                            " The slot uses an unchecked payload downcast."
                            if unchecked
                            else ""
                        )
                    ),
                    file=rel,
                    line=p["line"],
                    function=name,
                    category="uninit-object",
                    details={
                        "payload": name,
                        "slots": sorted(set(slot_types[name])),
                        "unchecked_downcast": unchecked,
                        "check": "uninitialized_object_slot",
                    },
                )
            )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(
        discovery, findings, functions_analyzed=payloads_analyzed
    )
    report["uninit_scan"] = {
        "note": (
            "CONSIDER — most heuristic check; enumerates the shape (payload slot "
            "+ no Constructor), the agent verifies the slot actually reads the "
            "payload without a re-check on a T.__new__(T) instance."
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
