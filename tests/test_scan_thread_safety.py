"""Tests for scan_thread_safety.py — the thread-safety-auditor (Class F)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_thread_safety")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestThreadSafety(unittest.TestCase):
    def test_refcell_payload_with_unsafe_sync_flagged(self) -> None:
        # The HamtObject shape: #[pyclass] payload with a RefCell + unsafe impl Sync.
        src = """
#[pyclass(module = "contextvars", name = "Context")]
#[derive(Debug)]
struct HamtObject {
    hamt: RefCell<Hamt>,
}
unsafe impl Sync for HamtObject {}
"""
        r = _run({"crates/stdlib/src/contextvars.rs": src})
        f = [x for x in r["findings"] if x["details"]["struct"] == "HamtObject"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")
        self.assertEqual(f[0]["confidence"], "HIGH")
        self.assertIn("RefCell", f[0]["details"]["interior_mutability"])

    def test_atomiccell_payload_not_flagged(self) -> None:
        # The migrated-safe form: AtomicCell is Sync — must NOT match `Cell`.
        src = """
#[pyclass(module = "itertools", name = "cycle")]
#[derive(Debug)]
struct PyCycle {
    index: AtomicCell<usize>,
    stop: AtomicCell<bool>,
}
"""
        r = _run({"crates/vm/src/stdlib/itertools.rs": src})
        self.assertEqual(r["findings"], [])

    def test_arc_mutex_payload_not_flagged(self) -> None:
        # Arc<Mutex<..>> is Sync — `Rc` must NOT match `Arc`.
        src = """
#[pyclass(module = "_thread", name = "lock")]
#[derive(Debug)]
struct PyLock {
    inner: Arc<Mutex<LockData>>,
}
"""
        r = _run({"crates/vm/src/stdlib/_thread.rs": src})
        self.assertEqual(r["findings"], [])

    def test_embedded_struct_flagged(self) -> None:
        # ContextInner (Cell) embedded in #[pyclass] PyContext; unsafe impl Sync
        # is on the inner struct → flagged as embedded-in-a-payload.
        src = """
struct ContextInner {
    idx: Cell<usize>,
    entered: Cell<bool>,
}
unsafe impl Sync for ContextInner {}

#[pyclass(module = "contextvars", name = "Context")]
#[derive(Debug)]
struct PyContext {
    inner: ContextInner,
}
"""
        r = _run({"crates/stdlib/src/contextvars.rs": src})
        f = [x for x in r["findings"] if x["details"]["struct"] == "ContextInner"]
        self.assertEqual(len(f), 1)
        self.assertFalse(f[0]["details"]["is_pyclass_payload"])

    def test_refcell_without_unsafe_sync_not_flagged(self) -> None:
        # A struct with a RefCell but no `unsafe impl Sync` and not reachable
        # from a #[pyclass] is single-thread-internal → not forced Sync → skip.
        src = """
struct InternalHelper {
    cache: RefCell<Vec<u8>>,
}
"""
        r = _run({"crates/vm/src/foo.rs": src})
        self.assertEqual(r["findings"], [])

    def test_tuple_struct_newtype_flagged(self) -> None:
        # FrameUnsafeCell(UnsafeCell<T>) — a tuple-struct newtype embedded in a
        # #[pyclass] Frame, force-Sync. No named fields → the tuple fallback.
        src = """
struct FrameUnsafeCell<T>(UnsafeCell<T>);
unsafe impl<T: Send> Sync for FrameUnsafeCell<T> {}

#[pyclass(name = "frame")]
#[derive(Debug)]
struct Frame {
    iframe: FrameUnsafeCell<Option<InterpreterFrame>>,
}
"""
        r = _run({"crates/vm/src/frame.rs": src})
        f = [x for x in r["findings"] if x["details"]["struct"] == "FrameUnsafeCell"]
        self.assertEqual(len(f), 1)
        self.assertIn("UnsafeCell", f[0]["details"]["interior_mutability"])


if __name__ == "__main__":
    unittest.main()
