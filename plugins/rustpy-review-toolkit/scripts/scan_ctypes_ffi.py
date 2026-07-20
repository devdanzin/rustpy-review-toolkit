#!/usr/bin/env python3
"""ctypes-ffi-auditor — Class H: int/pointer marshalling in `_ctypes`.

`ctypes` is the one place RustPython is inherently memory-unsafe — it calls real
C via libffi. Two Python-reachable shapes, both narrow a Python int (unbounded)
to a C width:

  (a) `ctypes_int_narrow_panic`  — `.to_usize()/.to_isize()/... .expect(...)` /
      `.unwrap()` on a Python int. A too-large int aborts the VM where CPython
      masks to the C width (RUSTPY-0017, `c_char_p(2**64)`; `simple.rs:908`).
  (b) `ctypes_int_narrow_silent` — `.to_usize().unwrap_or(0)` feeding a pointer:
      an overflowing int silently becomes a WRONG pointer (`function.rs`,
      `pointer.rs` `at_address`) — a memory-safety divergence, not a crash.

Scope: `crates/vm/src/stdlib/_ctypes/` only. Overlaps two other agents (0017 is
also a panic-site finding; 0015 is also eager-collect).

**The load-bearing SAFE filter (the ctypes gotcha):** passing a *small int as a
pointer* segfaults in BOTH interpreters — that is the generic int-as-pointer
behaviour, NOT a bug. Only a **divergence** (CPython raises, RustPython crashes)
counts. The scanner is high-recall; the agent applies the differential.

Not pattern-matched here (manual review in the agent): the `Python float -> f64`
converter arm in `function.rs` (RUSTPY-0024) that FFI then treats as a pointer →
SIGSEGV where CPython raises `ArgumentError`.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from rust_ts_utils import parse_bytes, strip_comments  # noqa: E402
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    make_finding,
    parse_common_args,
    relative_path,
)

# An int-to-C-width narrowing terminated by a panic/silent-default. `\s*` spans
# the newline in the multi-line chain `x\n.to_usize()\n.expect(...)`.
_NARROW_RE = re.compile(
    r"\.to_(?:usize|isize|u32|u64|i32|i64|u16|i16|u8|i8)\s*\(\s*\)"
    r"\s*\.\s*(expect|unwrap|unwrap_or)\b"
)


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Scan `_ctypes` for int→C-width narrowing panics / silent truncations."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)

    findings: list[dict] = []
    files_analyzed = 0

    for path in files:
        rel = relative_path(path, project_root)
        if "_ctypes/" not in rel.replace("\\", "/"):
            continue
        try:
            source = path.read_bytes()
        except OSError:
            continue
        files_analyzed += 1
        parse_bytes(source)  # validate parse
        full = strip_comments(source).decode("utf-8", "replace")

        for m in _NARROW_RE.finditer(full):
            terminal = m.group(1)
            line = full[: m.start(1)].count("\n") + 1
            snippet = full.splitlines()[line - 1].strip()[:100]
            if terminal in ("expect", "unwrap"):
                findings.append(
                    make_finding(
                        "ctypes_int_narrow_panic",
                        classification="FIX" if terminal == "expect" else "CONSIDER",
                        confidence="HIGH" if terminal == "expect" else "MEDIUM",
                        description=(
                            f"a Python int is narrowed to a C width with "
                            f"`.{terminal}(...)` in _ctypes: `{snippet}`. An "
                            f"unbounded Python int (e.g. `2**64`) aborts the VM "
                            f"where CPython masks to the C width (the RUSTPY-0017 "
                            f"`c_char_p(2**64)` shape). Fix: return an OverflowError "
                            f"via `.ok_or_else(|| vm.new_overflow_error(...))?`."
                        ),
                        file=rel,
                        line=line,
                        function="",
                        category="ctypes",
                        details={
                            "terminal": terminal,
                            "check": "ctypes_int_narrow_panic",
                        },
                    )
                )
            else:  # unwrap_or → silent wrong pointer
                findings.append(
                    make_finding(
                        "ctypes_int_narrow_silent",
                        classification="CONSIDER",
                        confidence="MEDIUM",
                        description=(
                            f"a Python int is narrowed with "
                            f"`.unwrap_or(...)` in _ctypes: `{snippet}`. An "
                            f"overflowing int silently becomes a WRONG pointer/offset "
                            f"(no crash, no error) — a memory-safety divergence. "
                            f"Confirm whether CPython rejects the same value."
                        ),
                        file=rel,
                        line=line,
                        function="",
                        category="ctypes",
                        details={
                            "terminal": terminal,
                            "check": "ctypes_int_narrow_silent",
                        },
                    )
                )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(discovery, findings, functions_analyzed=files_analyzed)
    report["ctypes_scan"] = {
        "note": (
            "narrow to _ctypes/. SAFE filter (agent): a small-int-as-pointer "
            "segfaults in BOTH interpreters — only a CPython-raises/RustPython-"
            "crashes divergence is a bug. float->f64 (0024) is manual-review."
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
