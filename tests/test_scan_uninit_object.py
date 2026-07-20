"""Tests for scan_uninit_object.py — the uninitialized-object-auditor (Class E)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_uninit_object")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestUninitObject(unittest.TestCase):
    def test_slot_without_constructor_flagged(self) -> None:
        # The _sre Match shape: AsMapping slot touches payload, no Constructor.
        src = """
#[pyclass(module = "re", name = "Match")]
#[derive(Debug)]
struct Match {
    regs: Vec<(isize, isize)>,
    string: PyObjectRef,
}

impl AsMapping for Match {
    fn as_mapping() -> &'static PyMappingMethods {
        static M: PyMappingMethods = PyMappingMethods {
            subscript: atomic_func!(|m, needle, vm| Match::mapping_downcast(m).getitem(needle, vm)),
        };
        &M
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_sre.rs": src})
        f = [x for x in r["findings"] if x["details"]["payload"] == "Match"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")
        self.assertTrue(f[0]["details"]["unchecked_downcast"])

    def test_with_constructor_attr_not_flagged(self) -> None:
        # `#[pyclass(with(Constructor, AsMapping))]` defines __new__ → guarded.
        src = """
#[pyclass(module = "foo", name = "Safe")]
#[derive(Debug)]
struct PySafe {
    data: PyObjectRef,
}

#[pyclass(with(Constructor, AsMapping))]
impl PySafe {}

impl AsMapping for PySafe {
    fn as_mapping() -> &'static PyMappingMethods {
        static M: PyMappingMethods = PyMappingMethods {
            subscript: atomic_func!(|m, needle, vm| PySafe::mapping_downcast(m).getitem(needle, vm)),
        };
        &M
    }
}
"""
        r = _run({"crates/vm/src/builtins/safe.rs": src})
        self.assertEqual(r["findings"], [])

    def test_constructor_impl_not_flagged(self) -> None:
        # An `impl Constructor for T` defines __new__ → guarded.
        src = """
#[pyclass(module = "foo", name = "Ctor")]
#[derive(Debug)]
struct PyCtor {
    data: PyObjectRef,
}

impl Constructor for PyCtor {
    type Args = ();
    fn py_new(cls: PyTypeRef, _: Self::Args, vm: &VirtualMachine) -> PyResult {
        Ok(vm.ctx.none())
    }
}

impl AsSequence for PyCtor {
    fn as_sequence() -> &'static PySequenceMethods {
        static S: PySequenceMethods = PySequenceMethods {
            item: atomic_func!(|s, i, vm| PyCtor::sequence_downcast(s).getitem(i, vm)),
        };
        &S
    }
}
"""
        r = _run({"crates/vm/src/builtins/ctor.rs": src})
        self.assertEqual(r["findings"], [])

    def test_slot_new_method_discharges_constructor(self) -> None:
        # v0.2.1: a raw `#[pyslot] fn slot_new` defines __new__ (the PyRange shape)
        # even without `impl Constructor` → not flagged.
        src = """
#[pyclass(module = "builtins", name = "range")]
#[derive(Debug)]
struct PyRange {
    start: PyRef<PyInt>,
    stop: PyRef<PyInt>,
    step: PyRef<PyInt>,
}

#[pyclass(with(AsMapping))]
impl PyRange {
    #[pyslot]
    fn slot_new(cls: PyTypeRef, args: FuncArgs, vm: &VirtualMachine) -> PyResult {
        Ok(vm.ctx.none())
    }
}

impl AsMapping for PyRange {
    fn as_mapping() -> &'static PyMappingMethods {
        static M: PyMappingMethods = PyMappingMethods {
            subscript: atomic_func!(|m, needle, vm| PyRange::mapping_downcast(m).getitem(needle, vm)),
        };
        &M
    }
}
"""
        r = _run({"crates/vm/src/builtins/range.rs": src})
        self.assertFalse(
            [x for x in r["findings"] if x["details"]["payload"] == "PyRange"]
        )

    def test_no_protocol_slot_not_flagged(self) -> None:
        # A payload with only #[pymethod]s (no payload-touching slot) is not this
        # agent's concern (methods downcast-fail cleanly).
        src = """
#[pyclass(module = "foo", name = "Plain")]
#[derive(Debug)]
struct PyPlain {
    data: PyObjectRef,
}

#[pyclass]
impl PyPlain {
    #[pymethod]
    fn get(&self) -> PyObjectRef {
        self.data.clone()
    }
}
"""
        r = _run({"crates/vm/src/builtins/plain.rs": src})
        self.assertEqual(r["findings"], [])


if __name__ == "__main__":
    unittest.main()
