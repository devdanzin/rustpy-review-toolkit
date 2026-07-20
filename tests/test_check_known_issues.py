"""Tests for check_known_issues.py — the known-issues regression cross-reference."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

check = import_script("check_known_issues")


def _file_with_panic_at(line: int) -> str:
    """A file whose `.unwrap()` (py-reachable) sits at exactly 1-indexed ``line``."""
    lines = [""] * (line - 3)
    lines.append("#[pyfunction]")
    lines.append("fn confirmed(o: PyObjectRef, vm: &VirtualMachine) -> PyResult<()> {")
    lines.append("    let _x = o.downcast::<PyInt>().unwrap();")
    lines.append("    Ok(())")
    lines.append("}")
    return "\n".join(lines)


# RUSTPY-0003 in the catalog points at crates/vm/src/class.rs:87.
_CATALOG_PATH = "crates/vm/src/class.rs"
_CATALOG_LINE = 87


class TestKnownIssues(unittest.TestCase):
    def test_catalog_loads(self) -> None:
        # known_panics.tsv is the PANIC subset (Class A/B); the RUSTPY-0018
        # SIGSEGV is a Class C unsafe bug caught by unsafe-soundness, not here.
        catalog = check._load_catalog()
        self.assertGreaterEqual(len(catalog), 14)
        bug_ids = {b for b, _, _ in catalog}
        self.assertIn("RUSTPY-0003", bug_ids)  # class.rs static-type panic
        self.assertIn("RUSTPY-0009", bug_ids)  # staticmethod repr unwrap

    def test_present_when_panic_at_exact_line(self) -> None:
        files = {_CATALOG_PATH: _file_with_panic_at(_CATALOG_LINE)}
        with TempRustPythonWorkspace(files) as ws:
            r = check.analyze(str(ws.root))
        self.assertEqual(r["known_issues"]["bug_rollup"].get("RUSTPY-0003"), "present")
        present = [f for f in r["findings"] if f["function"] == "RUSTPY-0003"]
        self.assertTrue(present)
        self.assertEqual(present[0]["classification"], "FIX")

    def test_line_drifted_when_panic_moved(self) -> None:
        files = {_CATALOG_PATH: _file_with_panic_at(_CATALOG_LINE + 5)}
        with TempRustPythonWorkspace(files) as ws:
            r = check.analyze(str(ws.root))
        self.assertEqual(
            r["known_issues"]["bug_rollup"].get("RUSTPY-0003"), "line_drifted"
        )
        drifted = [f for f in r["findings"] if f["function"] == "RUSTPY-0003"]
        self.assertTrue(drifted)
        self.assertEqual(drifted[0]["classification"], "CONSIDER")
        self.assertEqual(drifted[0]["details"]["nearest_panic_line"], _CATALOG_LINE + 5)

    def test_absent_when_no_panic_in_file(self) -> None:
        files = {_CATALOG_PATH: "#[pyfunction]\nfn ok() {}\n"}
        with TempRustPythonWorkspace(files) as ws:
            r = check.analyze(str(ws.root))
        self.assertEqual(
            r["known_issues"]["bug_rollup"].get("RUSTPY-0003"), "likely_fixed"
        )

    def test_file_missing_status(self) -> None:
        # No class.rs at all → the RUSTPY-0003 site is file_missing.
        with TempRustPythonWorkspace({"crates/vm/src/other.rs": "fn x() {}\n"}) as ws:
            r = check.analyze(str(ws.root))
        entries = r["known_issues"]["per_bug"].get("RUSTPY-0003", [])
        self.assertTrue(entries)
        self.assertEqual(entries[0]["status"], "file_missing")


if __name__ == "__main__":
    unittest.main()
