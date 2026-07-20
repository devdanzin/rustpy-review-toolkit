"""Tests for scan_unsafe_soundness.py — the RUSTPY-0018 crown jewel + transmute."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_unsafe_soundness")


def _run(rust: str) -> dict:
    with TempRustPythonWorkspace({"crates/vm/src/object/ext.rs": rust}) as ws:
        return scan.analyze(str(ws.root))


# The RUSTPY-0018 shape: two impls cast the stored pointer to `Py<T>`, one to `T`.
_INCONSISTENT = """
impl<T: PyPayload> Deref for PyAtomicRef<T> {
    fn deref(&self) -> &Py<T> {
        unsafe {
            self.inner.load(Ordering::Relaxed).cast::<Py<T>>().as_ref().unwrap()
        }
    }
}

impl<T: PyPayload> PyAtomicRef<T> {
    fn load_raw(&self) -> *const Py<T> {
        self.inner.load(Ordering::Relaxed).cast::<Py<T>>()
    }
}

impl<T: fmt::Debug> fmt::Debug for PyAtomicRef<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            self.inner
                .load(Ordering::Relaxed)
                .cast::<T>()
                .as_ref()
                .fmt(f)
        }
    }
}
"""

_CONSISTENT = """
impl<T: PyPayload> Deref for PyAtomicRef<T> {
    fn deref(&self) -> &Py<T> {
        unsafe { self.inner.load(Ordering::Relaxed).cast::<Py<T>>().as_ref().unwrap() }
    }
}
impl<T: PyPayload> PyAtomicRef<T> {
    fn load_raw(&self) -> *const Py<T> {
        self.inner.load(Ordering::Relaxed).cast::<Py<T>>()
    }
}
"""


class TestCastInconsistency(unittest.TestCase):
    def test_detects_0018_shape_as_fix(self) -> None:
        r = _run(_INCONSISTENT)
        fix = [
            f for f in r["findings"] if f["type"] == "cross_method_cast_inconsistency"
        ]
        self.assertEqual(len(fix), 1)
        f = fix[0]
        self.assertEqual(f["classification"], "FIX")
        self.assertEqual(f["confidence"], "HIGH")
        self.assertEqual(f["details"]["outlier_cast"], "T")
        self.assertEqual(f["details"]["majority_cast"], "Py<T>")
        self.assertTrue(f["details"]["structurally_related"])

    def test_consistent_casts_produce_no_finding(self) -> None:
        r = _run(_CONSISTENT)
        self.assertEqual(
            [
                f
                for f in r["findings"]
                if f["type"] == "cross_method_cast_inconsistency"
            ],
            [],
        )


class TestHandleTransmute(unittest.TestCase):
    def test_unguarded_handle_transmute_is_consider(self) -> None:
        rust = """
fn convert(x: PyObjectRef) -> PyRef<PyInt> {
    unsafe { transmute(x) }
}
"""
        r = _run(rust)
        f = [f for f in r["findings"] if f["type"] == "unguarded_handle_transmute"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")

    def test_guarded_transmute_is_not_flagged(self) -> None:
        rust = """
fn convert(x: PyObjectRef, vm: &VirtualMachine) -> PyResult<PyRef<PyInt>> {
    <PyRef<PyInt> as TransmuteFromObject>::check(vm, &x)?;
    Ok(unsafe { transmute(x) })
}
"""
        r = _run(rust)
        self.assertEqual(
            [f for f in r["findings"] if f["type"] == "unguarded_handle_transmute"], []
        )

    def test_non_handle_transmute_ignored(self) -> None:
        rust = """
fn bits(x: f64) -> u64 {
    unsafe { transmute(x) }
}
"""
        r = _run(rust)
        self.assertEqual(
            [f for f in r["findings"] if f["type"] == "unguarded_handle_transmute"], []
        )

    def test_prose_safety_comment_recorded_not_reclassified(self) -> None:
        # A prose `// SAFETY:` comment is surfaced as a sub-signal but does NOT
        # discharge the finding (the scanner can't verify prose).
        rust = """
fn as_untyped(x: PyRef<PyTuple>) -> PyRef<PyObjectRef> {
    // SAFETY: PyRef<T> has the same layout as PyObjectRef
    unsafe { transmute(x) }
}
"""
        r = _run(rust)
        f = [f for f in r["findings"] if f["type"] == "unguarded_handle_transmute"]
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0]["details"]["prose_safety_comment"])
        self.assertEqual(f[0]["classification"], "CONSIDER")

    def test_no_prose_safety_comment(self) -> None:
        rust = """
fn convert(x: PyObjectRef) -> PyRef<PyInt> {
    unsafe { transmute(x) }
}
"""
        r = _run(rust)
        f = [f for f in r["findings"] if f["type"] == "unguarded_handle_transmute"]
        self.assertEqual(len(f), 1)
        self.assertFalse(f[0]["details"]["prose_safety_comment"])


if __name__ == "__main__":
    unittest.main()
