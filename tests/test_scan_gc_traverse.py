"""Tests for scan_gc_traverse.py — the first-class GC Traverse auditor."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_gc_traverse")


def _run(rust: str) -> list[dict]:
    with TempRustPythonWorkspace({"crates/vm/src/builtins/x.rs": rust}) as ws:
        return scan.analyze(str(ws.root))["findings"]


def _of_type(findings: list[dict], t: str) -> list[dict]:
    return [f for f in findings if f["type"] == t]


class TestMissingTraverse(unittest.TestCase):
    def test_ref_owning_payload_without_traverse_flagged(self) -> None:
        rust = """
#[pyclass(name = "Thing")]
pub struct PyThing {
    items: PyRwLock<Vec<PyObjectRef>>,
}
"""
        f = _of_type(_run(rust), "missing_traverse")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")
        self.assertEqual(f[0]["confidence"], "MEDIUM")  # container of refs = strong
        self.assertTrue(f[0]["details"]["owns_container_of_refs"])

    def test_scalar_ref_is_low_confidence(self) -> None:
        rust = """
#[pyclass(name = "Method")]
pub struct PyMethod {
    callable: PyObjectRef,
}
"""
        f = _of_type(_run(rust), "missing_traverse")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["confidence"], "LOW")

    def test_payload_with_traverse_not_flagged(self) -> None:
        rust = """
#[pyclass(name = "Thing", traverse)]
pub struct PyThing {
    items: PyRwLock<Vec<PyObjectRef>>,
}
"""
        self.assertEqual(_of_type(_run(rust), "missing_traverse"), [])

    def test_non_ref_owning_payload_not_flagged(self) -> None:
        rust = """
#[pyclass(name = "Counter")]
pub struct PyCounter {
    count: AtomicU32,
    name: String,
}
"""
        self.assertEqual(_of_type(_run(rust), "missing_traverse"), [])

    def test_struct_closure_resolves_indirect_ownership(self) -> None:
        # PyFrozenSet owns refs only transitively through PySetInner.
        rust = """
pub struct PySetInner {
    content: Vec<PyObjectRef>,
}

#[pyclass(name = "frozenset")]
pub struct PyFrozenSet {
    inner: PySetInner,
}
"""
        f = _of_type(_run(rust), "missing_traverse")
        names = {x["details"]["payload"] for x in f}
        self.assertIn("PyFrozenSet", names)


class TestPyExceptionSupport(unittest.TestCase):
    """The #[pyexception] blind-spot fix (from the exceptions.rs meta-eval)."""

    def test_pyexception_custom_payload_forgotten_traverse_is_caught(self) -> None:
        # A #[pyexception] payload that owns a ref field but declares no
        # traverse — the recall gap the meta-eval surfaced. Now caught.
        rust = """
#[pyexception(name, base = PyException, ctx = "custom_error")]
#[repr(C)]
pub struct PyCustomError {
    base: PyException,
    payload: PyAtomicRef<Option<PyObject>>,
}
"""
        f = _of_type(_run(rust), "missing_traverse")
        names = {x["details"]["payload"] for x in f}
        self.assertIn("PyCustomError", names)

    def test_pyexception_with_manual_traverse_not_flagged(self) -> None:
        rust = """
#[pyexception(name, base = PyException, ctx = "stop_iteration", traverse = "manual")]
#[repr(C)]
pub struct PyStopIteration {
    base: PyException,
    value: PyAtomicRef<Option<PyObject>>,
}
"""
        self.assertEqual(_of_type(_run(rust), "missing_traverse"), [])

    def test_transparent_newtype_exception_not_flagged(self) -> None:
        # A #[pyexception] transparent newtype reuses its base's payload (empty
        # named-field list) → must NOT be a missing_traverse false positive.
        rust = """
#[pyexception(name, base = PyLookupError, ctx = "key_error", impl)]
#[repr(transparent)]
pub struct PyKeyError(PyLookupError);
"""
        self.assertEqual(_of_type(_run(rust), "missing_traverse"), [])


class TestSkipOnRefField(unittest.TestCase):
    def test_skip_on_bigint_field_is_correct_not_flagged(self) -> None:
        # The enumerate calibration: skip on `counter: PyRwLock<BigInt>` is fine.
        rust = """
#[pyclass(name = "enumerate", traverse)]
pub struct PyEnumerate {
    #[pytraverse(skip)]
    counter: PyRwLock<BigInt>,
    iterable: PyIter,
}
"""
        self.assertEqual(_of_type(_run(rust), "skip_on_ref_field"), [])

    def test_skip_on_ref_field_is_flagged(self) -> None:
        rust = """
#[pyclass(name = "Wrapper", traverse)]
pub struct PyWrapper {
    #[pytraverse(skip)]
    obj: PyObjectRef,
    tag: u32,
}
"""
        f = _of_type(_run(rust), "skip_on_ref_field")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["confidence"], "HIGH")
        self.assertEqual(f[0]["details"]["field"], "obj")


class TestManualTraverseGap(unittest.TestCase):
    def test_manual_traverse_missing_field_flagged(self) -> None:
        rust = """
#[pyclass(name = "list", traverse = "manual")]
pub struct PyList {
    elements: PyRwLock<Vec<PyObjectRef>>,
    extra: PyObjectRef,
}

impl Traverse for PyList {
    fn traverse(&self, tracer_fn: &mut TraverseFn<'_>) {
        self.elements.traverse(tracer_fn);
    }
}
"""
        f = _of_type(_run(rust), "manual_traverse_gap")
        self.assertEqual(len(f), 1)
        self.assertIn("extra", f[0]["details"]["missing_fields"])
        self.assertNotIn("elements", f[0]["details"]["missing_fields"])

    def test_manual_traverse_covering_all_fields_not_flagged(self) -> None:
        rust = """
#[pyclass(name = "list", traverse = "manual")]
pub struct PyList {
    elements: PyRwLock<Vec<PyObjectRef>>,
}

impl Traverse for PyList {
    fn traverse(&self, tracer_fn: &mut TraverseFn<'_>) {
        self.elements.traverse(tracer_fn);
    }
}
"""
        self.assertEqual(_of_type(_run(rust), "manual_traverse_gap"), [])


if __name__ == "__main__":
    unittest.main()
