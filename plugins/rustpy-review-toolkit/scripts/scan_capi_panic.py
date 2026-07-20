#!/usr/bin/env python3
"""capi-panic-boundary — panics and unguarded pointer derefs across the C ABI.

`crates/capi` is RustPython's CPython-C-API shim: **62 `pub extern "C" fn`** that
C code calls directly. The crate has **zero `catch_unwind`** anywhere, and its
entry idiom (`with_vm(...)` + `FfiResult::into_output`) only converts an `Err`
into a per-type sentinel — it does **not** catch a `panic!`. So any `.unwrap()` /
`.expect(...)` / `panic!` reached inside an `extern "C" fn` unwinds across the C
ABI = undefined behaviour (an abort at best, memory corruption at worst).

Two checks (both confined to `crates/capi/`):

  (a) `capi_panic_boundary` — an `extern "C" fn` whose body can panic
      (`.unwrap()`/`.expect(`/`panic!`/`unreachable!`/`unimplemented!`/`todo!`),
      with no `catch_unwind` guard (there is none in the crate).
  (b) `capi_null_deref` — an `unsafe { &*arg }` / `&mut *arg` deref of a
      caller-supplied `*mut`/`*const` parameter with no `.is_null()` / `NonNull`
      guard earlier in the function → segfault on a NULL argument.

**Honest framing (like gc-traverse): 0 fuzzer-confirmed instances.** The fuzzing
campaign never exercised `crates/capi`; this agent enters from the static
cross-application experiment (design §2/§7). Findings are CONSIDER — a real
UB surface, but whether a given panic/NULL is actually reachable from a
well-formed C caller is human judgment. `#[cfg(test)]` bodies are excluded.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from rust_ts_utils import (  # noqa: E402
    extract_attributes,
    extract_fn_items,
    find_enclosing,
    parse_bytes,
    strip_comments,
    text_of,
)
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    make_finding,
    parse_common_args,
    relative_path,
)

# Panic-producing tokens reachable inside an extern "C" fn body: (needle, label).
_PANIC_TOKENS: tuple[tuple[str, str], ...] = (
    (".unwrap()", "unwrap"),
    (".expect(", "expect"),
    ("panic!", "panic"),
    ("unreachable!", "unreachable"),
    ("unimplemented!", "unimplemented"),
    ("todo!", "todo"),
)

# A caller-supplied raw-pointer parameter: `obj: *mut PyObject`, `p: *const T`.
_RAW_PTR_PARAM_RE = re.compile(r"\b(\w+)\s*:\s*\*\s*(?:mut|const)\b")


# A deref of such a pointer: `&*obj`, `& mut *obj`, `&**obj`.
def _deref_re(name: str) -> re.Pattern[str]:
    return re.compile(rf"&\s*(?:mut\s+)?\*+\s*{re.escape(name)}\b")


def _is_cfg_test(attrs: list[dict]) -> bool:
    return any(
        a.get("name") == "cfg" and "test" in (a.get("args_text") or "") for a in attrs
    )


def _is_test_gated(node: object, source: bytes) -> bool:
    """True if the fn or an enclosing `mod` carries `#[cfg(test)]`."""
    if _is_cfg_test(extract_attributes(node, source)):  # type: ignore[arg-type]
        return True
    cur = node
    while True:
        mod = find_enclosing(cur, "mod_item")  # type: ignore[arg-type]
        if mod is None:
            return False
        if _is_cfg_test(extract_attributes(mod, source)):
            return True
        cur = mod


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan `crates/capi` for panics / unguarded derefs across the C ABI."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)

    findings: list[dict] = []
    extern_fns_analyzed = 0

    for path in files:
        rel = relative_path(path, project_root)
        if "crates/capi/" not in rel.replace("\\", "/"):
            continue  # C-ABI boundary lives only in the capi crate
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        stripped = strip_comments(source).decode("utf-8", "replace").splitlines()

        for fn in extract_fn_items(tree, source):
            if fn["extern_abi"] != "C":
                continue
            if _is_test_gated(fn["node"], source):
                continue
            body = fn["body_node"]
            if body is None:
                continue
            extern_fns_analyzed += 1
            b_start = body.start_point[0] + 1
            b_end = body.end_point[0] + 1
            body_lines = stripped[b_start - 1 : b_end]
            body_text = "\n".join(body_lines)

            # (a) panic tokens in the body → panic across the ABI.
            panic_sites: list[dict] = []
            for offset, raw in enumerate(body_lines):
                for needle, label in _PANIC_TOKENS:
                    if needle in raw:
                        panic_sites.append({"line": b_start + offset, "token": label})
                        break
            if panic_sites:
                first = panic_sites[0]["line"]
                toks = sorted({s["token"] for s in panic_sites})
                findings.append(
                    make_finding(
                        "capi_panic_boundary",
                        classification="CONSIDER",
                        confidence="MEDIUM",
                        description=(
                            f'extern "C" fn `{fn["name"]}` can panic '
                            f"({', '.join(toks)}) with no `catch_unwind` in the "
                            f"crate — a panic here unwinds across the C ABI (UB). "
                            f"{len(panic_sites)} panic site(s); confirm reachability "
                            f"from a well-formed C caller."
                        ),
                        file=rel,
                        line=first,
                        function=fn["name"],
                        category="capi",
                        details={
                            "extern_fn": fn["name"],
                            "panic_sites": [s["line"] for s in panic_sites],
                            "panic_tokens": toks,
                            "no_catch_unwind": True,
                            "check": "capi_panic_boundary",
                        },
                    )
                )

            # (b) unguarded raw-pointer deref of a parameter.
            params_text = (
                text_of(fn["params_node"], source) if fn["params_node"] else ""
            )
            ptr_params = _RAW_PTR_PARAM_RE.findall(params_text)
            unguarded: list[str] = []
            first_deref: int | None = None
            for name in ptr_params:
                dr = _deref_re(name)
                m = dr.search(body_text)
                if m is None:
                    continue
                guarded = (
                    f"{name}.is_null()" in body_text
                    or f"NonNull::new({name}" in body_text
                    or f"!{name}.is_null()" in body_text
                )
                if guarded:
                    continue
                unguarded.append(name)
                # line of the first deref of this arg
                upto = body_text[: m.start()]
                dl = b_start + upto.count("\n")
                if first_deref is None or dl < first_deref:
                    first_deref = dl
            if unguarded and first_deref is not None:
                findings.append(
                    make_finding(
                        "capi_null_deref",
                        classification="CONSIDER",
                        confidence="MEDIUM",
                        description=(
                            f'extern "C" fn `{fn["name"]}` dereferences '
                            f"caller-supplied pointer(s) "
                            f"{', '.join(f'`{a}`' for a in unguarded)} "
                            f"(`&*{unguarded[0]}`) with no `.is_null()` / `NonNull` "
                            f"guard — a NULL argument from C segfaults."
                        ),
                        file=rel,
                        line=first_deref,
                        function=fn["name"],
                        category="capi",
                        details={
                            "extern_fn": fn["name"],
                            "unguarded_ptr_args": unguarded,
                            "check": "capi_null_deref",
                        },
                    )
                )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(
        discovery, findings, functions_analyzed=extern_fns_analyzed
    )
    report["capi_scan"] = {
        "extern_c_fns_analyzed": extern_fns_analyzed,
        "note": (
            "experimental — 0 fuzzer-confirmed instances; crates/capi has no "
            "catch_unwind, so any reachable panic is UB across the C ABI"
        ),
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
