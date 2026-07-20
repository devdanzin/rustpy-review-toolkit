#!/usr/bin/env python3
"""GC Traverse-completeness auditor — the first-class GC agent.

RustPython has a cycle-collecting garbage collector: a `#[pyclass]` payload
opts into it by declaring `traverse` (auto `#[derive(Traverse)]`) or
`traverse = "manual"` (a hand-written `impl Traverse`). The `Traverse::traverse`
body must visit *every* owned `PyObjectRef`/`PyRef` exactly once; a payload that
owns Python references but declares no traverse is invisible to the collector,
so a reference cycle through it can never be collected — a leak.

This is this session's addition to the toolkit and is honestly framed:
**first-class but experimental — the surface is real (the `unsafe trait Traverse`
contract + the derive opt-in gap) but the fuzzing campaign found ZERO confirmed
instances** (it never examined the collector). Findings are therefore CONSIDER,
not FIX: whether an uncollectable cycle is actually reachable requires judging
whether the type participates in cycles, which is human work.

Three checks (all reuse the mapper's `extract_pyclass_payloads`):

  (a) `missing_traverse`     — a `#[pyclass]` payload with owned-ref fields but
                               no `traverse` / `traverse = "manual"`.
  (b) `skip_on_ref_field`    — `#[pytraverse(skip)]` on a field whose type owns a
                               Python ref (the derive silently drops it). A skip
                               on a NON-owning field (`PyRwLock<BigInt>`, an
                               atomic) is correct and is NOT flagged.
  (c) `manual_traverse_gap`  — a `traverse = "manual"` payload whose hand-written
                               `impl Traverse` body never mentions an owned-ref
                               field (a field-coverage miss).

Ownership is resolved with an intra-file struct closure: a field whose type is
another local struct that itself owns refs (e.g. `inner: PySetInner`) counts as
owning, even though its type text contains no ref token.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import _bare_ident, extract_pyclass_payloads  # noqa: E402
from rust_ts_utils import (  # noqa: E402
    extract_impl_blocks,
    extract_struct_defs,
    parse_bytes,
    text_of,
)
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    load_data_file,
    make_finding,
    parse_common_args,
    relative_path,
)

_DEFAULT_REF_TOKENS = (
    "PyObjectRef",
    "PyObject",
    "PyRef",
    "PyIter",
    "PyStackRef",
    "PyBaseExceptionRef",
    "PyExceptionRef",
    "PyWeak",
)


def _load_ref_tokens() -> list[str]:
    """Ref-owning type tokens from the data file (fallback to the default)."""
    data = load_data_file("gc_managed_types.json")
    tokens = data.get("ref_owning_tokens") if isinstance(data, dict) else None
    if isinstance(tokens, list) and tokens:
        return [str(t) for t in tokens]
    return list(_DEFAULT_REF_TOKENS)


def _contains_token(type_text: str, tokens: list[str]) -> bool:
    """True if any token appears as a word in the type text."""
    return any(
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(t)}", type_text) for t in tokens
    )


def _build_struct_ownership(
    all_structs: list[dict], ref_tokens: list[str]
) -> dict[str, bool]:
    """Fixpoint: which local structs (by name) transitively own a Python ref.

    A struct owns a ref if any field's type contains a ref token OR names
    another local struct that owns a ref (resolves `inner: PySetInner`).
    """
    fields_by_struct: dict[str, list[str]] = {
        sd["name"]: [f.get("type", "") for f in sd["fields"]] for sd in all_structs
    }
    owns: dict[str, bool] = {name: False for name in fields_by_struct}
    # Seed: direct ref tokens.
    for name, ftypes in fields_by_struct.items():
        if any(_contains_token(ft, ref_tokens) for ft in ftypes):
            owns[name] = True
    # Propagate: a field naming an owning struct makes this struct owning.
    changed = True
    while changed:
        changed = False
        owning_names = [n for n, v in owns.items() if v]
        for name, ftypes in fields_by_struct.items():
            if owns[name]:
                continue
            for ft in ftypes:
                if any(re.search(rf"\b{re.escape(o)}\b", ft) for o in owning_names):
                    owns[name] = True
                    changed = True
                    break
    return owns


def _field_owns_ref(
    field_type: str, ref_tokens: list[str], owning_structs: dict[str, bool]
) -> bool:
    """True if a field type owns a Python ref (directly or via a local struct)."""
    if _contains_token(field_type, ref_tokens):
        return True
    for name, is_owning in owning_structs.items():
        if is_owning and re.search(rf"\b{re.escape(name)}\b", field_type):
            return True
    return False


# Collection wrappers that make an owned ref a *container* of Python objects —
# a far stronger reference-cycle candidate than a single scalar back-reference.
_COLLECTION_RE = re.compile(
    r"\b(?:Vec|VecDeque|HashMap|IndexMap|BTreeMap|HashSet|IndexSet|BTreeSet)\s*<|\["
)


def _owns_container_of_refs(owned_fields: list[dict], ref_tokens: list[str]) -> bool:
    """True if any owned field is a *collection* of Python refs (Vec/map/slice).

    A container of Python objects is a strong cycle candidate (it can hold an
    object that refers back); a single scalar `callable: PyObjectRef` is a weak
    one (usually a non-cyclic back-reference). Used to rank missing_traverse.
    """
    for f in owned_fields:
        ft = f["type"]
        if _COLLECTION_RE.search(ft) and _contains_token(ft, ref_tokens):
            return True
    return False


def _manual_traverse_bodies(tree: object, source: bytes) -> dict[str, str]:
    """Map payload-name → text of its `impl Traverse for <Name>` body."""
    out: dict[str, str] = {}
    for ib in extract_impl_blocks(tree, source):
        if ib["trait"] and _bare_ident(ib["trait"]) == "Traverse":
            name = _bare_ident(ib["type"])
            body = ib["body_node"]
            if name and body is not None:
                out[name] = text_of(body, source)
    return out


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan RustPython for GC Traverse-completeness gaps."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    ref_tokens = _load_ref_tokens()

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

        all_structs = extract_struct_defs(tree, source)
        owning = _build_struct_ownership(all_structs, ref_tokens)
        payloads = extract_pyclass_payloads(tree, source, default_module)
        manual_bodies = _manual_traverse_bodies(tree, source)

        for p in payloads:
            payloads_analyzed += 1
            owned_fields = [
                f for f in p["fields"] if _field_owns_ref(f["type"], ref_tokens, owning)
            ]
            if not owned_fields:
                continue  # nothing to trace — no GC obligation
            topt = p["traverse_option"]
            derive = p["has_derive_traverse"]

            # (a) missing traverse entirely. Rank by whether an owned field is a
            # container of refs (strong cycle candidate) vs a single scalar ref
            # (weak — often a non-cyclic back-reference).
            if topt is None and not derive:
                strong = _owns_container_of_refs(owned_fields, ref_tokens) or (
                    len(owned_fields) >= 2
                )
                confidence = "MEDIUM" if strong else "LOW"
                names = ", ".join(f"`{f['name']}: {f['type']}`" for f in owned_fields)
                findings.append(
                    make_finding(
                        "missing_traverse",
                        classification="CONSIDER",
                        confidence=confidence,
                        description=(
                            f"`{p['rust_name']}` (Python `{p['python_name']}`) is a "
                            f"#[pyclass] that owns Python reference field(s) {names} "
                            f'but declares no `traverse` / `traverse = "manual"`. '
                            f"It is invisible to the cycle collector — a reference "
                            f"cycle through it is uncollectable. Confirm whether the "
                            f"type can participate in a cycle."
                        ),
                        file=rel,
                        line=p["line"],
                        function=p["rust_name"],
                        category="gc-traverse",
                        details={
                            "payload": p["rust_name"],
                            "owned_ref_fields": [f["name"] for f in owned_fields],
                            "owns_container_of_refs": strong,
                            "check": "missing_traverse",
                        },
                    )
                )

            # (b) skip on a ref-owning field.
            for f in owned_fields:
                if f["skip"]:
                    findings.append(
                        make_finding(
                            "skip_on_ref_field",
                            classification="CONSIDER",
                            confidence="HIGH",
                            description=(
                                f"`{p['rust_name']}` field `{f['name']}: {f['type']}` "
                                f"owns a Python reference but is marked "
                                f"`#[pytraverse(skip)]` — the derived Traverse will "
                                f"NOT visit it, so a cycle through it leaks. A skip is "
                                f"only correct on a non-ref-owning field."
                            ),
                            file=rel,
                            line=p["line"],
                            function=p["rust_name"],
                            category="gc-traverse",
                            details={
                                "payload": p["rust_name"],
                                "field": f["name"],
                                "field_type": f["type"],
                                "check": "skip_on_ref_field",
                            },
                        )
                    )

            # (c) manual traverse missing an owned-ref field.
            if topt == "manual":
                body = manual_bodies.get(p["rust_name"], "")
                if body:
                    missing = [
                        f["name"]
                        for f in owned_fields
                        if not f["skip"]
                        and not re.search(rf"\b{re.escape(f['name'])}\b", body)
                    ]
                    if missing:
                        findings.append(
                            make_finding(
                                "manual_traverse_gap",
                                classification="CONSIDER",
                                confidence="MEDIUM",
                                description=(
                                    f"`{p['rust_name']}`'s hand-written "
                                    f"`impl Traverse` body never mentions owned-ref "
                                    f"field(s) {', '.join(f'`{m}`' for m in missing)}. "
                                    f"If they hold Python references, the manual "
                                    f"traverse misses them (a collector leak)."
                                ),
                                file=rel,
                                line=p["line"],
                                function=p["rust_name"],
                                category="gc-traverse",
                                details={
                                    "payload": p["rust_name"],
                                    "missing_fields": missing,
                                    "check": "manual_traverse_gap",
                                },
                            )
                        )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(
        discovery, findings, functions_analyzed=payloads_analyzed
    )
    report["gc_scan"] = {
        "note": "experimental — 0 fuzzer-confirmed instances; findings are CONSIDER"
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
