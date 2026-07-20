#!/usr/bin/env python3
"""debug-format-auditor — Class I: unsound `{:?}` on a Python object.

A native error message that formats a Python object with `{:?}` (Rust `Debug`)
instead of Python `repr` has two harms: it dumps internal struct state, and — the
fatal one — it can reach an **unsound `Debug` impl** that reinterprets raw memory.
The confirmed root is `PyAtomicRef<T>`'s `Debug` (`object/ext.rs:278`, RUSTPY-0018)
which `.cast::<T>()`s a pointer that actually points at `Py<T>` → reads garbage →
SIGSEGV, reachable from any `{:?}` that transitively formats one.

Two checks:
  (a) `unsound_debug_impl` — a hand-written `impl Debug` whose `fmt` body
      reinterprets a raw pointer (`.cast::<...>()` / `transmute`). This is the
      root class (also owned by unsafe-soundness for the cross-method-cast angle);
      its *presence* is what makes the triggers below SIGSEGV-severity.
  (b) `debug_format_trigger` — a `{:?}` / `{:#?}` inside a `vm.new_*_error(...)`
      user-facing error message (the site that Debug-formats a Python object).

**Severity gating (design):** while an `unsound_debug_impl` exists (0018 is live),
a trigger is a SIGSEGV path (CONSIDER→FIX on a traced reach). If the root is
fixed, the class drops to cosmetic (garbage-message) severity. The scan reports
`report.debug_scan.unsound_debug_exists` so the agent knows which regime it is in.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import _bare_ident  # noqa: E402
from rust_ts_utils import extract_impl_blocks, parse_bytes, strip_comments  # noqa: E402
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    make_finding,
    parse_common_args,
    relative_path,
)

# A raw-pointer reinterpretation inside a Debug `fmt` body.
_RAW_PTR_READ_RE = re.compile(r"\.cast::<|\btransmute\b")
# A Debug-format specifier: `{:?}` or `{:#?}` (optionally named/positional).
_DEBUG_FMT_RE = re.compile(r"\{[^{}]*:#?\?\}")
# A user-facing error constructor (ranks the trigger higher).
_NEW_ERROR_RE = re.compile(r"new_\w*err\w*\s*\(", re.IGNORECASE)
# A format-producing macro / constructor whose output is user-visible.
_FORMAT_CTX_RE = re.compile(
    r"\b(?:format!|write!|writeln!|format_args!)\s*\(|new_\w*err\w*\s*\("
)
# The formatted argument looks like a *Python object* (the harm) rather than a
# Rust primitive — so `{:?}` reaches a PyObject Debug (possibly the unsound one).
_PYOBJ_HINT_RE = re.compile(
    r"\.as_object\(|\.into_object\(|\.to_pyobject|\.class\(\)|\.__|\bzelf\b|\bobj\b"
    r"|PyObjectRef|PyObject\b"
)


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan RustPython for unsound Debug impls + `{:?}`-on-pyobject triggers."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)

    findings: list[dict] = []
    impls_analyzed = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        rel = relative_path(path, project_root)
        stripped = strip_comments(source).decode("utf-8", "replace").splitlines()

        # (a) unsound Debug impls — a raw-pointer read in a Debug fmt body.
        for ib in extract_impl_blocks(tree, source):
            if not ib["trait"] or _bare_ident(ib["trait"]) != "Debug":
                continue
            impls_analyzed += 1
            body = ib["body_node"]
            if body is None:
                continue
            b_start = body.start_point[0] + 1
            b_end = body.end_point[0] + 1
            body_text = "\n".join(stripped[b_start - 1 : b_end])
            if _RAW_PTR_READ_RE.search(body_text):
                findings.append(
                    make_finding(
                        "unsound_debug_impl",
                        classification="CONSIDER",
                        confidence="MEDIUM",
                        description=(
                            f"`impl Debug for {ib['type']}` reinterprets a raw "
                            f"pointer in `fmt` (`.cast::<...>()` / transmute). If the "
                            f"cast target differs from the stored pointer's real "
                            f"type, `{{:?}}` reads garbage → SIGSEGV (the RUSTPY-0018 "
                            f"PyAtomicRef shape). Cross-check the stored type against "
                            f"the sibling accessors (unsafe-soundness owns that)."
                        ),
                        file=rel,
                        line=ib["start_line"],
                        function=f"Debug for {ib['type']}",
                        category="debug-format",
                        details={
                            "debug_for": ib["type"],
                            "check": "unsound_debug_impl",
                        },
                    )
                )

        # (b) triggers — `{:?}` Debug-formatting a Python object into a
        # user-visible string. Require a format context AND a Python-object hint
        # in the argument window (so `{:?}` on a Rust primitive is not flagged).
        for i, line in enumerate(stripped):
            if not _FORMAT_CTX_RE.search(line):
                continue
            window = "\n".join(stripped[i : i + 4])  # the call may wrap
            if not _DEBUG_FMT_RE.search(window):
                continue
            in_error = bool(_NEW_ERROR_RE.search(window))
            # In an error message a `{:?}` is inherently suspect (almost always the
            # offending object). In a plain format!/write! require a Python-object
            # hint so `{:?}` on a Rust primitive is not flagged.
            if not in_error and not _PYOBJ_HINT_RE.search(window):
                continue
            findings.append(
                make_finding(
                    "debug_format_trigger",
                    classification="CONSIDER",
                    confidence="HIGH" if in_error else "MEDIUM",
                    description=(
                        "a `{:?}` / `{:#?}` Debug-formats what looks like a Python "
                        "object"
                        + (" into a user-facing error message" if in_error else "")
                        + ". A PyObjectRef/PyRef/Py should use Python `repr`, not "
                        "Rust Debug — and Rust Debug can transitively reach an "
                        "unsound Debug impl (SIGSEGV). Confirm the argument type."
                    ),
                    file=rel,
                    line=i + 1,
                    function="",
                    category="debug-format",
                    details={
                        "check": "debug_format_trigger",
                        "in_error_message": in_error,
                    },
                )
            )

    findings = deduplicate_findings(findings)
    unsound_exists = any(f["type"] == "unsound_debug_impl" for f in findings)
    report = build_rustpy_report(discovery, findings, functions_analyzed=impls_analyzed)
    report["debug_scan"] = {
        "unsound_debug_exists": unsound_exists,
        "note": (
            "severity-gated: while an unsound Debug impl exists (RUSTPY-0018 live), "
            "a trigger is a SIGSEGV path; if the root is fixed it is cosmetic."
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
