"""Tests for map_rustpy_internals.py — the classification engine."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

mapper = import_script("map_rustpy_internals")
rtu = import_script("rust_ts_utils")


def _classify(source: str, module: str = "builtins") -> list[dict]:
    tree = rtu.parse_bytes(source.encode())
    return mapper.classify_functions(tree, source.encode(), module)


def _by_name(fns: list[dict], rust_name: str) -> dict:
    return next(f for f in fns if f["rust_name"] == rust_name)


class TestClassifyFunctions(unittest.TestCase):
    def test_pymethod_is_py_tier(self) -> None:
        src = """
impl PyFoo {
    #[pymethod]
    fn bar(&self) {}
}
"""
        f = _by_name(_classify(src), "bar")
        self.assertEqual(f["reachable"], "py")
        self.assertEqual(f["kind"], "method")
        self.assertEqual(f["python_name"], "bar")
        self.assertEqual(f["class"], "PyFoo")
        self.assertEqual(f["qualified_name"], "PyFoo.bar")

    def test_pymethod_magic_dunder(self) -> None:
        src = """
impl PyFoo {
    #[pymethod(magic)]
    fn repr(&self) {}
}
"""
        f = _by_name(_classify(src), "repr")
        self.assertEqual(f["python_name"], "__repr__")
        self.assertEqual(f["reachable"], "py")

    def test_name_override(self) -> None:
        src = """
impl PyFoo {
    #[pymethod(name = "custom")]
    fn internal_ident(&self) {}
}
"""
        f = _by_name(_classify(src), "internal_ident")
        self.assertEqual(f["python_name"], "custom")

    def test_pyfunction_free_fn_is_py(self) -> None:
        src = """
#[pyfunction]
fn my_builtin() {}
"""
        f = _by_name(_classify(src), "my_builtin")
        self.assertEqual(f["reachable"], "py")
        self.assertEqual(f["kind"], "function")
        self.assertIsNone(f["class"])

    def test_protocol_trait_impl_is_protocol_tier(self) -> None:
        src = """
impl Representable for PyFoo {
    fn repr_str(&self, vm: &VirtualMachine) -> PyResult<String> {
        Ok(String::new())
    }
}
"""
        f = _by_name(_classify(src), "repr_str")
        self.assertEqual(f["reachable"], "protocol")
        self.assertEqual(f["kind"], "protocol")
        self.assertEqual(f["trait"], "Representable")

    def test_non_protocol_trait_impl_is_internal(self) -> None:
        # A non-protocol trait (e.g. From) is not Python-reachable via slots.
        src = """
impl From<PyObjectRef> for PyFoo {
    fn from(o: PyObjectRef) -> Self { todo!() }
}
"""
        f = _by_name(_classify(src), "from")
        self.assertEqual(f["reachable"], "internal")

    def test_plain_helper_is_internal(self) -> None:
        src = """
impl PyFoo {
    fn helper(&self) {}
}
"""
        f = _by_name(_classify(src), "helper")
        self.assertEqual(f["reachable"], "internal")
        self.assertEqual(f["kind"], "helper")

    def test_pymodule_sets_module_context(self) -> None:
        src = """
#[pymodule(name = "_special")]
mod inner {
    #[pyfunction]
    fn thing() {}
}
"""
        fns = _classify(src, module="default_dir")
        f = _by_name(fns, "thing")
        self.assertEqual(f["module"], "_special")

    def test_getset_setter_kind(self) -> None:
        src = """
impl PyFoo {
    #[pygetset]
    fn value(&self) {}
    #[pygetset(setter)]
    fn set_value(&self) {}
}
"""
        fns = _classify(src)
        self.assertEqual(_by_name(fns, "value")["kind"], "getset")
        self.assertEqual(_by_name(fns, "set_value")["kind"], "getset-setter")


class TestExtractPyclassPayloads(unittest.TestCase):
    def _payloads(self, source: str) -> list[dict]:
        tree = rtu.parse_bytes(source.encode())
        return mapper.extract_pyclass_payloads(tree, source.encode(), "builtins")

    def test_traverse_manual(self) -> None:
        src = """
#[pyclass(module = false, name = "list", traverse = "manual")]
pub struct PyList {
    elements: PyRwLock<Vec<PyObjectRef>>,
}
"""
        p = self._payloads(src)[0]
        self.assertEqual(p["traverse_option"], "manual")
        self.assertEqual(p["python_name"], "list")

    def test_traverse_auto_bare(self) -> None:
        src = """
#[pyclass(module = false, name = "enumerate", traverse)]
pub struct PyEnumerate {
    counter: PyRwLock<BigInt>,
    iterable: PyIter,
}
"""
        p = self._payloads(src)[0]
        self.assertEqual(p["traverse_option"], "auto")
        names = {f["name"] for f in p["fields"]}
        self.assertEqual(names, {"counter", "iterable"})

    def test_traverse_absent(self) -> None:
        src = """
#[pyclass(module = false, name = "frozenset")]
pub struct PyFrozenSet {
    inner: PySetInner,
}
"""
        p = self._payloads(src)[0]
        self.assertIsNone(p["traverse_option"])

    def test_pytraverse_skip_flag(self) -> None:
        src = """
#[pyclass(traverse)]
pub struct PyEnumerate {
    #[pytraverse(skip)]
    counter: PyRwLock<BigInt>,
    iterable: PyIter,
}
"""
        p = self._payloads(src)[0]
        skipped = {f["name"] for f in p["fields"] if f["skip"]}
        self.assertEqual(skipped, {"counter"})


class TestMapperAnalyze(unittest.TestCase):
    def test_analyze_produces_orientation(self) -> None:
        files = {
            "crates/vm/src/builtins/foo.rs": """
#[pyclass(name = "Foo", traverse)]
pub struct PyFoo { item: PyObjectRef }

impl PyFoo {
    #[pymethod]
    fn method_a(&self) {}
    fn helper(&self) {}
}

impl Representable for PyFoo {
    fn repr_str(&self) -> String { String::new() }
}
""",
        }
        with TempRustPythonWorkspace(files) as ws:
            report = mapper.analyze(str(ws.root))
        o = report["orientation"]
        self.assertEqual(o["reachability_tiers"]["py"], 1)
        self.assertEqual(o["reachability_tiers"]["protocol"], 1)
        self.assertEqual(o["reachability_tiers"]["internal"], 1)
        self.assertEqual(o["class_count"], 1)
        self.assertEqual(report["crate_info"]["runtime"], "rustpython")


if __name__ == "__main__":
    unittest.main()
