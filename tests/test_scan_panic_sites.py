"""Tests for scan_panic_sites.py — the flagship panic-site auditor."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_panic_sites")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestPanicSites(unittest.TestCase):
    def test_py_tier_unwrap_with_high_signal_is_fix(self) -> None:
        # A #[pymethod] that downcasts a Python object then unwraps → FIX.
        src = """
impl PyFoo {
    #[pymethod]
    fn convert(&self, obj: PyObjectRef, vm: &VirtualMachine) -> PyResult<()> {
        let n = obj.downcast::<PyInt>().unwrap();
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        fix = [f for f in r["findings"] if f["classification"] == "FIX"]
        self.assertTrue(fix, "expected a FIX for py-tier unwrap on a downcast")
        self.assertEqual(fix[0]["details"]["tier"], "py")
        self.assertIn("downcast_or_coerce", fix[0]["details"]["reachability_signals"])

    def test_protocol_tier_repr_unwrap_is_surfaced(self) -> None:
        # The staticmethod-repr shape (RUSTPY-0009): Representable slot unwraps.
        src = """
impl Representable for PyFoo {
    fn repr_str(&self, vm: &VirtualMachine) -> PyResult<String> {
        let s = self.value.repr(vm).unwrap();
        Ok(s)
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertEqual(f["details"]["tier"], "protocol")
        self.assertIn(f["classification"], ("FIX", "CONSIDER"))

    def test_internal_tier_silenced_by_default(self) -> None:
        src = """
impl PyFoo {
    fn helper(&self) -> u32 {
        self.cache.get().unwrap()
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["panic_scan"]["internal_sites_suppressed"], 1)

    def test_include_internal_reveals_helper(self) -> None:
        src = """
impl PyFoo {
    fn helper(&self) -> u32 {
        self.cache.get().unwrap()
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src}, include_internal=True)
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["findings"][0]["classification"], "ACCEPTABLE")
        self.assertEqual(r["findings"][0]["details"]["tier"], "internal")

    def test_args_index_arity_pattern(self) -> None:
        # The _typing._idfunc shape: indexing args[0] without an arity check.
        src = """
#[pyfunction]
fn idfunc(args: FuncArgs, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
    Ok(args.args[0].clone())
}
"""
        r = _run({"crates/vm/src/stdlib/typing.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "args-index")
        self.assertEqual(f["details"]["tier"], "py")
        self.assertIn("user_index_or_arity", f["details"]["reachability_signals"])

    def test_comment_line_is_skipped(self) -> None:
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self) {
        // this.unwrap() is only in a comment
        let x = 1;
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        self.assertEqual(r["findings"], [])

    def test_explicit_panic_macro_is_consider(self) -> None:
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self) {
        panic!("should not happen");
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "panic")
        self.assertEqual(f["classification"], "CONSIDER")

    def test_weak_invariant_signal_downgrades(self) -> None:
        # A downcast (high signal) but a nearby "// SAFETY:" weak-invariant note
        # → CONSIDER, not FIX.
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self, obj: PyObjectRef) -> PyResult<()> {
        // SAFETY: checked above that obj is always a PyInt
        let n = obj.downcast::<PyInt>().unwrap();
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertTrue(f["details"]["weak_invariant_signal"])
        self.assertEqual(f["classification"], "CONSIDER")


if __name__ == "__main__":
    unittest.main()
