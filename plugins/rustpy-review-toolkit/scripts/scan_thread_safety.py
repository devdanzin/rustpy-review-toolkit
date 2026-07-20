#!/usr/bin/env python3
"""thread-safety-auditor — Class F: non-Sync interior mutability on a shared payload.

RustPython has **no `unsendable`** (that is a PyO3-ism — 0 occurrences here).
Instead, the `threading` feature — an **always-on default** — blanket-impls
`Send + Sync` for every `#[pyclass]` payload (`PyThreadingConstraint`,
`object/payload.rs`). A payload that holds single-thread interior mutability
(`Cell`/`RefCell`/`UnsafeCell`/`Rc`) is therefore NOT auto-`Sync`, and only
compiles because someone wrote a **hand-written `unsafe impl Sync for X`**. Under
`PYTHON_GIL=0` two threads can reach the same object and the interior mutability
races: `RefCell` → `BorrowMutError` panic; `Cell`/`UnsafeCell` → torn read / UB.

The scanner flags a struct that is **all three** of:
  1. force-marked `Sync`/`Send` via a hand-written `unsafe impl Sync|Send for X`,
  2. holding a `Cell`/`RefCell`/`UnsafeCell`/`Rc` field, and
  3. reachable from a `#[pyclass]` payload (itself a payload, or embedded in one).

The word-boundary matcher excludes the SAFE migrated forms automatically:
`AtomicCell` (crossbeam, Sync) does not match `Cell`, and `Arc` does not match
`Rc`. So the fuzzer's old F sites that upstream migrated to `AtomicCell`
(`itertools`) / `Arc<Mutex>` (`_thread`) are correctly NOT flagged; the live
cluster (`contextvars`, `frame`) is.

**Calibration: CONSIDER, not FIX** — a static thread-safety candidate cannot be
confirmed without a *concurrency* differential (spawn threads, `PYTHON_GIL=0`),
which is dynamic. The already-fuzzer-confirmed F *panics* (0019/0020) still reach
FIX through the `known-issues` catalog cross-reference, not through this scanner.
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

_DEFAULT_UNSAFE_IM = ("Cell", "RefCell", "UnsafeCell", "Rc")
# RefCell/Cell race → a guaranteed BorrowMutError panic under contention (the
# strongest F shape, 0001/0019); UnsafeCell/Rc → UB / non-atomic RMW (may be
# hand-synchronized), ranked a notch lower.
_HIGH_RISK = ("Cell", "RefCell")


def _load_im_tokens() -> list[str]:
    data = load_data_file("interior_mutability_types.json")
    toks = data.get("unsafe_interior_mutability") if isinstance(data, dict) else None
    if isinstance(toks, list) and toks:
        return [str(t) for t in toks]
    return list(_DEFAULT_UNSAFE_IM)


def _im_fields(field_type: str, tokens: list[str]) -> list[str]:
    """Interior-mutability tokens present in a field type (word-boundary match).

    `\\bCell\\s*<` does NOT match `AtomicCell<` (Sync-safe) and `\\bRc\\s*<`
    does NOT match `Arc<` — the boundary handles the safe/unsafe split.
    """
    return [t for t in tokens if re.search(rf"\b{re.escape(t)}\s*<", field_type)]


def _reachable_from_pyclass(
    struct_fields: dict[str, list[str]], pyclass_names: set[str]
) -> set[str]:
    """Downward closure: structs reachable from a #[pyclass] payload's fields.

    A pyclass payload P with a field of type Y makes Y reachable; Y's fields
    make their struct types reachable; etc. (resolves `iframe: FrameUnsafeCell`,
    `PyContext { inner: ContextInner }`).
    """
    reachable = {n for n in pyclass_names if n in struct_fields}
    all_names = list(struct_fields)
    changed = True
    while changed:
        changed = False
        for name in list(reachable):
            for ft in struct_fields.get(name, []):
                for other in all_names:
                    if other not in reachable and re.search(
                        rf"\b{re.escape(other)}\b", ft
                    ):
                        reachable.add(other)
                        changed = True
    return reachable


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan RustPython for non-Sync interior mutability on shared payloads."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    im_tokens = _load_im_tokens()

    findings: list[dict] = []
    structs_analyzed = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        rel = relative_path(path, project_root)
        default_module = path.parent.name

        structs = extract_struct_defs(tree, source)
        payloads = extract_pyclass_payloads(tree, source, default_module)
        pyclass_names = {p["rust_name"] for p in payloads}
        struct_fields = {
            sd["name"]: [f["type"] for f in sd["fields"]] for sd in structs
        }
        reachable = _reachable_from_pyclass(struct_fields, pyclass_names)

        # Types force-marked Sync/Send by a hand-written `unsafe impl`.
        forced_sync: dict[str, int] = {}
        for ib in extract_impl_blocks(tree, source):
            if not ib["is_unsafe"] or not ib["trait"]:
                continue
            if _bare_ident(ib["trait"]) in ("Sync", "Send"):
                forced_sync.setdefault(_bare_ident(ib["type"]), ib["start_line"])

        struct_line = {sd["name"]: sd["start_line"] for sd in structs}
        for sd in structs:
            structs_analyzed += 1
            name = sd["name"]
            if name not in forced_sync or name not in reachable:
                continue
            hits = [
                (f["name"], f["type"], _im_fields(f["type"], im_tokens))
                for f in sd["fields"]
            ]
            im_hits = [(fn, ft, toks) for (fn, ft, toks) in hits if toks]
            # Tuple-struct newtypes (`FrameUnsafeCell(UnsafeCell<T>)`) have no
            # named fields — fall back to scanning the struct definition text.
            struct_toks = _im_fields(text_of(sd["node"], source), im_tokens)
            if not im_hits and not struct_toks:
                continue
            all_toks = sorted(
                {t for (_, _, toks) in im_hits for t in toks} | set(struct_toks)
            )
            high = any(t in _HIGH_RISK for t in all_toks)
            is_pyclass = name in pyclass_names
            fields_desc = (
                ", ".join(f"`{fn}: {ft}`" for (fn, ft, _) in im_hits)
                if im_hits
                else f"(a tuple-struct newtype over {'/'.join(struct_toks)})"
            )
            where = (
                "(a #[pyclass] payload)"
                if is_pyclass
                else "(embedded in a #[pyclass] payload)"
            )
            race_note = (
                "a RefCell/Cell race is a guaranteed BorrowMutError panic under "
                "contention"
                if high
                else "a torn read / UB"
            )
            findings.append(
                make_finding(
                    "thread_unsafe_interior_mutability",
                    classification="CONSIDER",
                    confidence="HIGH" if high else "MEDIUM",
                    description=(
                        f"`{name}` {where} holds non-Sync interior mutability "
                        f"{fields_desc} and is force-marked `unsafe impl Sync/Send "
                        f"for {name}` — under the always-on `threading` blanket two "
                        f"Python threads can reach it and race the "
                        f"{'/'.join(all_toks)} ({race_note})."
                    ),
                    file=rel,
                    line=struct_line.get(name, forced_sync[name]),
                    function=name,
                    category="thread-safety",
                    details={
                        "struct": name,
                        "is_pyclass_payload": is_pyclass,
                        "interior_mutability": all_toks,
                        "im_fields": [fn for (fn, _, _) in im_hits],
                        "unsafe_sync_impl_line": forced_sync[name],
                        "check": "thread_unsafe_interior_mutability",
                    },
                )
            )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(
        discovery, findings, functions_analyzed=structs_analyzed
    )
    report["thread_safety_scan"] = {
        "note": (
            "CONSIDER — static candidates; confirmation needs a concurrency "
            "differential (PYTHON_GIL=0). No `unsendable` in RustPython; the "
            "signal is `unsafe impl Sync` over Cell/RefCell/UnsafeCell/Rc."
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
