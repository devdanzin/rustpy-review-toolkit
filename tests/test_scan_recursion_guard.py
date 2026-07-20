"""Tests for scan_recursion_guard.py — the recursion-guard-auditor (Class D)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_recursion_guard")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestRecursionGuard(unittest.TestCase):
    def test_unguarded_hash_recursion_flagged(self) -> None:
        # The genericalias shape: __hash__ recurses over args with no guard.
        src = """
impl Hashable for PyGenericAlias {
    fn hash(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyHash> {
        let mut h = 0;
        for arg in zelf.args.iter() {
            h ^= arg.hash(vm)?;
        }
        Ok(h)
    }
}
"""
        r = _run({"crates/vm/src/builtins/genericalias.rs": src})
        f = [x for x in r["findings"] if x["details"]["class"] == "PyGenericAlias"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")

    def test_guarded_repr_not_flagged(self) -> None:
        # __repr__ that DOES take a ReprGuard is safe → not flagged (the asymmetry).
        src = """
impl Representable for PyTuple {
    fn repr_str(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<String> {
        let _guard = match ReprGuard::enter(vm, zelf.as_object()) {
            Some(g) => g,
            None => return Ok("(...)".to_owned()),
        };
        let mut s = String::new();
        for elem in zelf.elements.iter() {
            s.push_str(&elem.repr(vm)?);
        }
        Ok(s)
    }
}
"""
        r = _run({"crates/vm/src/builtins/tuple.rs": src})
        self.assertFalse(
            [x for x in r["findings"] if x["details"]["class"] == "PyTuple"]
        )

    def test_scalar_hash_not_flagged(self) -> None:
        # A __hash__ that touches a fixed field (no iteration) cannot recurse
        # deeply → not flagged even though it calls .hash(vm).
        src = """
impl Hashable for PyBoundMethod {
    fn hash(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyHash> {
        let a = zelf.function.hash(vm)?;
        Ok(a)
    }
}
"""
        r = _run({"crates/vm/src/builtins/function.rs": src})
        self.assertFalse(
            [x for x in r["findings"] if x["details"]["class"] == "PyBoundMethod"]
        )

    def test_dispatch_guarded_compare_not_flagged(self) -> None:
        # v0.2.1: `.rich_compare(` recursion is DISPATCH-guarded (PyObject::_cmp
        # wraps with_recursion) → a cmp slot recursing via it is NOT flagged.
        src = """
impl Comparable for PyUnion {
    fn cmp(zelf: &Py<Self>, other: &PyObject, op: PyComparisonOp, vm: &VirtualMachine) -> PyResult<PyComparisonValue> {
        for (a, b) in zelf.args.iter().zip(other_args.iter()) {
            if !a.rich_compare(b, op, vm)?.to_bool() {
                return Ok(false.into());
            }
        }
        Ok(true.into())
    }
}
"""
        r = _run({"crates/vm/src/builtins/union.rs": src})
        self.assertFalse(
            [
                x
                for x in r["findings"]
                if x["details"].get("class") == "PyUnion"
                and x["type"] == "unguarded_protocol_recursion"
            ]
        )

    def test_parameter_walk_recursion_flagged(self) -> None:
        # v0.2.1: the RUSTPY-0007a / CPython #154275 class — a make_parameters
        # helper that self-recurses over a collection with no guard.
        src = """
fn make_parameters_from_slice(args: &[PyObjectRef], vm: &VirtualMachine) -> PyTupleRef {
    let mut parameters = Vec::new();
    for arg in args.iter() {
        if let Some(subparams) = arg.get_attr(...) {
            let sub = make_parameters_from_slice(&items, vm);
            parameters.extend(sub);
        }
    }
    PyTuple::new_ref(parameters, &vm.ctx)
}
"""
        r = _run({"crates/vm/src/builtins/genericalias.rs": src})
        f = [
            x
            for x in r["findings"]
            if x["type"] == "unguarded_parameter_walk_recursion"
        ]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["details"]["cpython_issue"], "154275")

    def test_guarded_parameter_walk_not_flagged(self) -> None:
        # The same walk WITH a with_recursion guard is safe → not flagged.
        src = """
fn make_parameters_from_slice(args: &[PyObjectRef], vm: &VirtualMachine) -> PyResult<PyTupleRef> {
    vm.with_recursion("make_parameters", || {
        let mut parameters = Vec::new();
        for arg in args.iter() {
            let sub = make_parameters_from_slice(&items, vm)?;
            parameters.extend(sub);
        }
        Ok(PyTuple::new_ref(parameters, &vm.ctx))
    })
}
"""
        r = _run({"crates/vm/src/builtins/genericalias.rs": src})
        self.assertFalse(
            [
                x
                for x in r["findings"]
                if x["type"] == "unguarded_parameter_walk_recursion"
            ]
        )


if __name__ == "__main__":
    unittest.main()
