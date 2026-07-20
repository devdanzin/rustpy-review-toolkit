#!/usr/bin/env python3
"""Unsafe-soundness auditor: the RustPython object-model crown jewel (Class C).

Two RustPython-native heuristics over the raw-pointer machinery in the object
model, both doubly-confirmed (the fuzzer's SIGSEGV finding + this session's
unsafe-agent pass):

1. **Cross-method pointer-cast inconsistency** (the RUSTPY-0018 `PyAtomicRef`
   shape, highest severity). A type stores a raw pointer in a field and reads it
   back via ``.load(...).cast::<X>()`` in several methods. If one method casts
   to a *different, structurally-related* type than its siblings — e.g. `Debug`
   casts the stored `Py<T>` pointer to `.cast::<T>()` while `Deref`/`load_raw`
   cast to `.cast::<Py<T>>()` — that method dereferences the wrong memory
   layout: a SIGSEGV a Python program triggers by, e.g., `repr()`-ing the object
   (RUSTPY-0018, a one-character fix). This is the flagship of this scanner.

2. **Handle-type transmute without a visible guard.** A ``transmute`` between
   Python handle types (`PyObjectRef`/`PyRef`/`Py<T>`/`PyObject`) is sound ONLY
   over a `#[repr(transparent)]` layout or after a ``TransmuteFromObject::check``.
   Flag transmutes in a function whose body shows neither the check nor a
   documented `repr(transparent)` SAFETY note — a CONSIDER for the agent to
   verify (most are sound; the scanner is deliberately high-recall here).

RustPython's object model is `unsafe`-dense by nature; this scanner does NOT
flag bare `unsafe` blocks (that would be all noise). It fires only on these two
specific, load-bearing shapes.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from rust_ts_utils import extract_fn_items, extract_impl_blocks, parse_bytes  # noqa: E402
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    make_finding,
    parse_common_args,
    relative_path,
)
from map_rustpy_internals import _bare_ident  # noqa: E402

# `.load(<args>).cast::<TYPE>()` — a stored-atomic load-then-cast. The TYPE
# (turbofish) is what the raw pointer is being interpreted as. DOTALL so the
# method-chain newline between `.load(...)` and `.cast` is spanned.
_LOAD_CAST_RE = re.compile(
    rb"\.load\s*\([^()]*\)\s*\.cast\s*::\s*<\s*(.+?)\s*>\s*\(", re.DOTALL
)

# A transmute call (with or without turbofish).
_TRANSMUTE_RE = re.compile(rb"\btransmute\s*(?:::\s*<.*?>)?\s*\(", re.DOTALL)

# Handle-type tokens whose transmute needs a repr(transparent)/check guard.
_HANDLE_TOKENS = (
    "PyObjectRef",
    "PyRef",
    "Py<",
    "PyObject",
    "Borrowed",
    "PyStackRef",
)

# Tokens that discharge a handle transmute's soundness obligation.
_TRANSMUTE_GUARD_TOKENS = (
    "TransmuteFromObject",
    "::check",
    "transparent",
    "repr(transparent)",
)


def _line_of(source: bytes, offset: int) -> int:
    """1-indexed line number of a byte offset."""
    return source.count(b"\n", 0, offset) + 1


def _related(a: str, b: str) -> bool:
    """True if two cast types are structurally related (one wraps the other).

    The RUSTPY-0018 shape is `T` vs `Py<T>`: the outlier's type is the inner
    generic argument of the majority's. Detected by the `<inner>` substring.
    """
    a, b = a.strip(), b.strip()
    if a == b:
        return False
    return f"<{a}>" in b or f"<{b}>" in a or f"< {a} >" in b or f"< {b} >" in a


def _check_cast_inconsistency(
    source: bytes, tree: object, rel: str, findings: list[dict]
) -> None:
    """Flag cross-method load-then-cast inconsistency within one type's impls."""
    impls = extract_impl_blocks(tree, source)
    # Group impl byte-ranges by their self-type bare ident.
    groups: dict[str, list[tuple[int, int]]] = {}
    for ib in impls:
        ident = _bare_ident(ib["type"])
        if not ident:
            continue
        node = ib["node"]
        groups.setdefault(ident, []).append((node.start_byte, node.end_byte))

    for ident, ranges in groups.items():
        # Collect (cast_type, offset, line) for every load-cast inside the group.
        casts: list[tuple[str, int, int]] = []
        for m in _LOAD_CAST_RE.finditer(source):
            off = m.start()
            if not any(lo <= off < hi for lo, hi in ranges):
                continue
            ctype = m.group(1).decode("utf-8", "replace").strip()
            casts.append((ctype, off, _line_of(source, off)))
        if len(casts) < 2:
            continue
        distinct = {c[0] for c in casts}
        if len(distinct) < 2:
            continue  # all methods agree — sound
        # Majority type = the consistent interpretation; minority = the outlier.
        counts: dict[str, int] = {}
        for ctype, _, _ in casts:
            counts[ctype] = counts.get(ctype, 0) + 1
        majority = max(counts, key=lambda k: counts[k])
        for ctype, _offset, line in casts:
            if ctype == majority:
                continue
            related = _related(ctype, majority)
            classification = "FIX" if related else "CONSIDER"
            confidence = "HIGH" if related else "MEDIUM"
            findings.append(
                make_finding(
                    "cross_method_cast_inconsistency",
                    classification=classification,
                    confidence=confidence,
                    description=(
                        f"`{ident}` reads its stored pointer as `.cast::<{ctype}>()` "
                        f"here, but as `.cast::<{majority}>()` in {counts[majority]} "
                        f"sibling method(s). If the stored pointer is a "
                        f"`{majority}`, this cast dereferences the wrong memory "
                        f"layout (the RUSTPY-0018 PyAtomicRef SIGSEGV shape)."
                    ),
                    file=rel,
                    line=line,
                    function=ident,
                    category="unsafe-soundness",
                    details={
                        "type": ident,
                        "outlier_cast": ctype,
                        "majority_cast": majority,
                        "majority_count": counts[majority],
                        "structurally_related": related,
                    },
                )
            )


def _check_unguarded_transmute(
    source: bytes, tree: object, rel: str, findings: list[dict]
) -> None:
    """Flag handle-type transmutes whose function shows no repr(transparent)/check."""
    for fn in extract_fn_items(tree, source):
        body = fn["body_node"]
        if body is None:
            continue
        body_bytes = source[body.start_byte : body.end_byte]
        if not _TRANSMUTE_RE.search(body_bytes):
            continue
        # Handle-type and guard tokens can appear in the SIGNATURE (param /
        # return types) as well as the body, so check the whole function text.
        node = fn["node"]
        fn_text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
        if not any(tok in fn_text for tok in _HANDLE_TOKENS):
            continue
        if any(tok in fn_text for tok in _TRANSMUTE_GUARD_TOKENS):
            continue  # a check/transparent guard is present in the fn — sound
        for m in _TRANSMUTE_RE.finditer(body_bytes):
            line = _line_of(source, body.start_byte + m.start())
            findings.append(
                make_finding(
                    "unguarded_handle_transmute",
                    classification="CONSIDER",
                    confidence="LOW",
                    description=(
                        f"`transmute` involving a Python handle type in "
                        f"`{fn['name']}` with no visible `TransmuteFromObject::check` "
                        f"or `repr(transparent)` SAFETY in the function. Verify the "
                        f"source and target are `#[repr(transparent)]`-compatible."
                    ),
                    file=rel,
                    line=line,
                    function=fn["name"],
                    category="unsafe-soundness",
                    details={"fn": fn["name"], "guard_seen": False},
                )
            )


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan RustPython's object model for the two unsafe-soundness shapes."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)

    findings: list[dict] = []
    fns_analyzed = 0
    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        rel = relative_path(path, project_root)
        _check_cast_inconsistency(source, tree, rel, findings)
        _check_unguarded_transmute(source, tree, rel, findings)
        fns_analyzed += len(extract_fn_items(tree, source))

    findings = deduplicate_findings(findings)
    return build_rustpy_report(discovery, findings, functions_analyzed=fns_analyzed)


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
