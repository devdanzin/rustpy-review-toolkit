"""Tests for scan_ctypes_ffi.py — the ctypes-ffi-auditor (Class H)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_ctypes_ffi")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestCtypesFfi(unittest.TestCase):
    def test_int_narrow_expect_is_fix(self) -> None:
        # RUSTPY-0017: c_char_p(2**64) — .to_usize().expect(...) → FIX.
        src = """
impl PyCSimple {
    fn to_arg(&self, vm: &VirtualMachine) -> usize {
        self.value.to_usize().expect("int too large for pointer")
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_ctypes/simple.rs": src})
        f = [x for x in r["findings"] if x["type"] == "ctypes_int_narrow_panic"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "FIX")

    def test_multiline_narrowing_caught(self) -> None:
        # The real simple.rs shape: narrowing and .expect on separate lines.
        src = """
impl PyCSimple {
    fn to_arg(&self, vm: &VirtualMachine) -> usize {
        self.value
            .to_usize()
            .expect("int too large for pointer")
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_ctypes/simple.rs": src})
        self.assertTrue(
            [x for x in r["findings"] if x["type"] == "ctypes_int_narrow_panic"]
        )

    def test_unwrap_or_is_silent_consider(self) -> None:
        src = """
impl PyCFuncPtr {
    fn addr(&self, vm: &VirtualMachine) -> usize {
        self.offset.to_usize().unwrap_or(0)
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_ctypes/function.rs": src})
        f = [x for x in r["findings"] if x["type"] == "ctypes_int_narrow_silent"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")

    def test_guarded_narrowing_not_flagged(self) -> None:
        # A narrowing that returns an error (ok_or_else) is safe → not flagged.
        src = """
impl PyCSimple {
    fn to_arg(&self, vm: &VirtualMachine) -> PyResult<usize> {
        self.value.to_usize().ok_or_else(|| vm.new_overflow_error("too big".to_owned()))
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_ctypes/simple.rs": src})
        self.assertEqual(r["findings"], [])

    def test_narrowing_outside_ctypes_ignored(self) -> None:
        # The same narrowing outside _ctypes/ is not this agent's concern.
        src = """
impl PyFoo {
    fn n(&self) -> usize {
        self.value.to_usize().expect("too big")
    }
}
"""
        r = _run({"crates/vm/src/stdlib/itertools.rs": src})
        self.assertEqual(r["findings"], [])


if __name__ == "__main__":
    unittest.main()
