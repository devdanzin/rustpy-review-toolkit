"""Tests for scan_debug_format.py — the debug-format-auditor (Class I)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_debug_format")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestDebugFormat(unittest.TestCase):
    def test_unsound_debug_impl_flagged(self) -> None:
        # The PyAtomicRef shape: a Debug fmt that .cast::<T>()s a raw pointer.
        src = """
impl<T: fmt::Debug> fmt::Debug for PyAtomicRef<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe { self.inner.load(Ordering::Relaxed).cast::<T>().as_ref().fmt(f) }
    }
}
"""
        r = _run({"crates/vm/src/object/ext.rs": src})
        f = [x for x in r["findings"] if x["type"] == "unsound_debug_impl"]
        self.assertEqual(len(f), 1)
        self.assertIn("PyAtomicRef", f[0]["details"]["debug_for"])
        self.assertTrue(r["debug_scan"]["unsound_debug_exists"])

    def test_benign_debug_impl_not_flagged(self) -> None:
        # A Debug that doesn't reinterpret a raw pointer is fine.
        src = """
impl fmt::Debug for PyThing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PyThing({})", self.name)
    }
}
"""
        r = _run({"crates/vm/src/object/thing.rs": src})
        self.assertFalse(
            [x for x in r["findings"] if x["type"] == "unsound_debug_impl"]
        )

    def test_debug_in_error_message_flagged(self) -> None:
        src = """
impl PyFoo {
    fn enter(&self, task: PyObjectRef, vm: &VirtualMachine) -> PyResult<()> {
        Err(vm.new_runtime_error(format!("Cannot enter into task {:?} while another", task)))
    }
}
"""
        r = _run({"crates/stdlib/src/_asyncio.rs": src})
        f = [x for x in r["findings"] if x["type"] == "debug_format_trigger"]
        self.assertTrue(f)
        self.assertTrue(f[0]["details"]["in_error_message"])
        self.assertEqual(f[0]["confidence"], "HIGH")

    def test_debug_of_pyobject_in_format_flagged(self) -> None:
        # format! (not an error) with {:?} on a Python object → flagged (MEDIUM).
        src = """
impl Representable for PyFoo {
    fn repr_str(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<String> {
        Ok(format!("{:?}.args", zelf.as_object()))
    }
}
"""
        r = _run({"crates/vm/src/stdlib/typevar.rs": src})
        f = [x for x in r["findings"] if x["type"] == "debug_format_trigger"]
        self.assertTrue(f)
        self.assertFalse(f[0]["details"]["in_error_message"])

    def test_debug_of_primitive_not_flagged(self) -> None:
        # {:?} on a Rust primitive in a plain format! (no Python-object hint).
        src = """
impl PyFoo {
    fn describe(&self) -> String {
        format!("count is {:?}", self.count)
    }
}
"""
        r = _run({"crates/vm/src/foo.rs": src})
        self.assertFalse(
            [x for x in r["findings"] if x["type"] == "debug_format_trigger"]
        )


if __name__ == "__main__":
    unittest.main()
