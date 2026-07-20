"""Tests for scan_capi_panic.py — the capi-panic-boundary auditor."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_capi_panic")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestCapiPanic(unittest.TestCase):
    def test_extern_fn_panic_is_flagged(self) -> None:
        src = """
#[unsafe(no_mangle)]
pub extern "C" fn PyFoo_Bar(x: i32) -> i32 {
    let v = do_something(x).unwrap();
    v
}
"""
        r = _run({"crates/capi/src/foo.rs": src})
        f = [x for x in r["findings"] if x["type"] == "capi_panic_boundary"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["classification"], "CONSIDER")
        self.assertTrue(f[0]["details"]["no_catch_unwind"])
        self.assertIn("unwrap", f[0]["details"]["panic_tokens"])

    def test_unguarded_ptr_deref_is_flagged(self) -> None:
        src = """
pub extern "C" fn PyFoo_Deref(obj: *mut PyObject) -> i32 {
    let o = unsafe { &*obj };
    o.thing()
}
"""
        r = _run({"crates/capi/src/obj.rs": src})
        f = [x for x in r["findings"] if x["type"] == "capi_null_deref"]
        self.assertEqual(len(f), 1)
        self.assertIn("obj", f[0]["details"]["unguarded_ptr_args"])

    def test_null_checked_deref_not_flagged(self) -> None:
        # A deref guarded by an is_null() check is safe → no capi_null_deref.
        src = """
pub extern "C" fn PyFoo_Safe(obj: *mut PyObject) -> i32 {
    if obj.is_null() {
        return -1;
    }
    let o = unsafe { &*obj };
    o.thing()
}
"""
        r = _run({"crates/capi/src/safe.rs": src})
        self.assertFalse([x for x in r["findings"] if x["type"] == "capi_null_deref"])

    def test_panic_free_extern_fn_not_flagged(self) -> None:
        src = """
pub extern "C" fn PyFoo_Clean(x: i32) -> i32 {
    x + 1
}
"""
        r = _run({"crates/capi/src/clean.rs": src})
        self.assertEqual(r["findings"], [])

    def test_cfg_test_extern_fn_excluded(self) -> None:
        # An extern fn inside a #[cfg(test)] mod must be excluded.
        src = """
#[cfg(test)]
mod tests {
    pub extern "C" fn helper_cb(obj: *mut PyObject) -> i32 {
        let o = unsafe { &*obj };
        do_thing().unwrap()
    }
}
"""
        r = _run({"crates/capi/src/gated.rs": src})
        self.assertEqual(r["findings"], [])

    def test_non_capi_crate_ignored(self) -> None:
        # The same panic outside crates/capi/ is not this agent's concern.
        src = """
pub extern "C" fn some_cb(obj: *mut PyObject) -> i32 {
    let o = unsafe { &*obj };
    do_thing().unwrap()
}
"""
        r = _run({"crates/vm/src/stdlib/foo.rs": src})
        self.assertEqual(r["findings"], [])


if __name__ == "__main__":
    unittest.main()
