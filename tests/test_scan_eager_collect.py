"""Tests for scan_eager_collect.py — the eager-collect-parity auditor (Class G)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_eager_collect")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestEagerCollect(unittest.TestCase):
    def test_known_gap_is_high(self) -> None:
        # RUSTPY-0012: _generate_suggestions eagerly binds `candidates: Vec<PyObjectRef>`.
        src = """
#[pyfunction]
fn _generate_suggestions(
    candidates: Vec<PyObjectRef>,
    name: PyObjectRef,
    vm: &VirtualMachine,
) -> PyObjectRef {
    calculate(candidates.iter(), &name)
}
"""
        r = _run({"crates/vm/src/stdlib/suggestions.rs": src})
        f = [x for x in r["findings"] if x["type"] == "eager_collect_parity"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["confidence"], "HIGH")
        self.assertEqual(f[0]["details"]["known_parity_gap"], "RUSTPY-0012")

    def test_generic_eager_param_is_low(self) -> None:
        src = """
#[pyfunction]
fn consume(items: Vec<PyObjectRef>, vm: &VirtualMachine) -> PyResult<()> {
    Ok(())
}
"""
        r = _run({"crates/vm/src/stdlib/foo.rs": src})
        f = [x for x in r["findings"] if x["type"] == "eager_collect_parity"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["confidence"], "LOW")

    def test_varargs_not_flagged(self) -> None:
        # A bare `args: Vec<PyObjectRef>` is bounded varargs → not flagged.
        src = """
#[pyfunction]
fn make(args: Vec<PyObjectRef>, vm: &VirtualMachine) -> PyResult<()> {
    Ok(())
}
"""
        r = _run({"crates/vm/src/builtins/set.rs": src})
        self.assertEqual(r["findings"], [])

    def test_lazy_vec_pyiter_not_flagged(self) -> None:
        # Vec<PyIter> is lazy (zip/map) → not flagged.
        src = """
#[pyfunction]
fn zip_impl(iters: Vec<PyIter>, vm: &VirtualMachine) -> PyResult<()> {
    Ok(())
}
"""
        r = _run({"crates/vm/src/builtins/zip.rs": src})
        self.assertEqual(r["findings"], [])

    def test_safe_function_not_flagged(self) -> None:
        # `all` short-circuits lazily — verified SAFE by name.
        src = """
#[pyfunction]
fn all(iterable: ArgIterable<PyObjectRef>, vm: &VirtualMachine) -> PyResult<bool> {
    Ok(true)
}
"""
        r = _run({"crates/vm/src/builtins/mod.rs": src})
        self.assertEqual(r["findings"], [])

    def test_internal_helper_not_flagged(self) -> None:
        # An eager param on an internal (non-exposed) helper is missed by design
        # (the interprocedural limitation) — not flagged.
        src = """
fn parse_filter_chain_spec(filter_specs: Vec<PyObjectRef>, vm: &VirtualMachine) -> PyResult<()> {
    Ok(())
}
"""
        r = _run({"crates/vm/src/stdlib/lzma.rs": src})
        self.assertEqual(r["findings"], [])


if __name__ == "__main__":
    unittest.main()
