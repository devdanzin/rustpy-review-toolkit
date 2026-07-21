#!/usr/bin/env python3
"""Cross-reference the confirmed-crash catalog against a fresh scan.

Backs the ``known-issues`` command. ``data/known_panics.tsv`` records the crash
sites confirmed as reproduced interpreter crashes from two sources — the ``fusil``
fuzzing campaign (``RUSTPY-*``) and this toolkit's static review, then reproduced
(``RPYR-*``) — each a ``crates/…:line`` signature. Note some recursion/segv sites
(e.g. RPYR-0013/0014 hash recursion) carry no panic token, so a fresh panic scan
reads them ``absent`` though unfixed — read the file to confirm. This script runs
a fresh panic-site scan (with ``--include-internal``, since several confirmed
sites live in internal helpers reached transitively) and reports, per catalog
entry, whether the site is:

  * ``present``      — a panic finding at exactly that file:line (still unfixed)
  * ``line_drifted`` — the file still has panic sites but not at that exact line
                       (the catalog was captured at a slightly different commit;
                       the bug may still be there a few lines away)
  * ``absent``       — the file has no panic sites (likely fixed or refactored)
  * ``file_missing`` — the file no longer exists

This is a static, drift-tolerant regression baseline — it does NOT run the
repros. A ``present`` site is a confirmed, reproduced crash still in the tree.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_panic_sites  # noqa: E402
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from scan_common import make_finding, parse_common_args  # noqa: E402

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_catalog() -> list[tuple[str, str, int]]:
    """Parse known_panics.tsv → list of (bug_id, rel_file, line)."""
    path = _DATA_DIR / "known_panics.tsv"
    out: list[tuple[str, str, int]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        bug_id, signature = parts[0].strip(), parts[1].strip()
        if ":" not in signature:
            continue
        file_part, _, line_part = signature.rpartition(":")
        try:
            out.append((bug_id, file_part, int(line_part)))
        except ValueError:
            continue
    return out


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Cross-reference the confirmed-panic catalog against a fresh scan."""
    discovery = discover(target)
    project_root = Path(discovery["project_root"])
    catalog = _load_catalog()

    # Fresh panic scan over the whole target, internal tier included (confirmed
    # sites live in internal helpers too).
    scan = scan_panic_sites.analyze(target, max_files=max_files, include_internal=True)
    lines_by_file: dict[str, set[int]] = {}
    for f in scan["findings"]:
        lines_by_file.setdefault(f["file"], set()).add(f["line"])

    findings: list[dict] = []
    status_counts = {
        "present": 0,
        "line_drifted": 0,
        "absent": 0,
        "file_missing": 0,
    }
    per_bug: dict[str, list[dict]] = {}

    for bug_id, rel_file, line in catalog:
        file_exists = (project_root / rel_file).is_file()
        file_lines = lines_by_file.get(rel_file, set())
        if not file_exists:
            status = "file_missing"
        elif line in file_lines:
            status = "present"
        elif file_lines:
            status = "line_drifted"
        else:
            status = "absent"
        status_counts[status] += 1

        nearest = None
        if file_lines and status == "line_drifted":
            nearest = min(file_lines, key=lambda ln: abs(ln - line))

        entry = {
            "bug_id": bug_id,
            "file": rel_file,
            "catalog_line": line,
            "status": status,
            "nearest_panic_line": nearest,
        }
        per_bug.setdefault(bug_id, []).append(entry)

        if status in ("present", "line_drifted"):
            classification = "FIX" if status == "present" else "CONSIDER"
            desc = (
                f"{bug_id}: confirmed panic site `{rel_file}:{line}` is still present "
                if status == "present"
                else f"{bug_id}: confirmed panic near `{rel_file}:{line}` "
                f"(catalog line drifted; nearest panic at line {nearest}) "
            )
            findings.append(
                make_finding(
                    "known_panic_still_present",
                    classification=classification,
                    confidence="HIGH" if status == "present" else "MEDIUM",
                    description=desc
                    + "— a fuzzer-confirmed, reproduced interpreter crash.",
                    file=rel_file,
                    line=nearest or line,
                    function=bug_id,
                    category="known-issue",
                    details=entry,
                )
            )

    report = build_rustpy_report(discovery, findings, functions_analyzed=len(catalog))
    # Per-bug rollup: a bug is "fixed" only if ALL its sites are absent/missing.
    bug_rollup: dict[str, str] = {}
    for bug_id, entries in per_bug.items():
        statuses = {e["status"] for e in entries}
        if statuses & {"present"}:
            bug_rollup[bug_id] = "present"
        elif statuses & {"line_drifted"}:
            bug_rollup[bug_id] = "line_drifted"
        else:
            bug_rollup[bug_id] = "likely_fixed"
    report["known_issues"] = {
        "catalog_entries": len(catalog),
        "distinct_bugs": len(per_bug),
        "site_status_counts": status_counts,
        "bug_rollup": dict(sorted(bug_rollup.items())),
        "per_bug": per_bug,
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
