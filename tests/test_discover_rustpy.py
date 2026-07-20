"""Tests for discover_rustpy.py — RustPython workspace detection + profiling."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

discover_rustpy = import_script("discover_rustpy")


class TestDiscoverRustPython(unittest.TestCase):
    def test_detects_workspace_via_rustpython_vm(self) -> None:
        files = {"crates/vm/src/builtins/list.rs": "pub fn f() {}\n"}
        with TempRustPythonWorkspace(files) as ws:
            d = discover_rustpy.discover(str(ws.root))
        self.assertTrue(d["is_rustpython"])
        self.assertFalse(d["out_of_scope"])
        self.assertEqual(d["detection_method"], "workspace_rustpython_vm")
        self.assertEqual(d["version"], "0.5.0")
        self.assertEqual(d["version_source"], "workspace.package")

    def test_threading_feature_detected(self) -> None:
        with TempRustPythonWorkspace({"crates/vm/src/lib.rs": ""}) as ws:
            d = discover_rustpy.discover(str(ws.root))
        self.assertTrue(d["threading_feature"])
        self.assertTrue(any("default" in s for s in d["threading_signals"]))

    def test_threading_off_when_not_default(self) -> None:
        with TempRustPythonWorkspace(
            {"crates/vm/src/lib.rs": ""}, threading_default=False
        ) as ws:
            d = discover_rustpy.discover(str(ws.root))
        # Feature is still declared, but not on by default.
        self.assertFalse(d["threading_feature"])

    def test_crate_roles_classified(self) -> None:
        with TempRustPythonWorkspace({"crates/vm/src/lib.rs": ""}) as ws:
            d = discover_rustpy.discover(str(ws.root))
        roles = d["crate_roles"]
        self.assertEqual(roles.get("vm"), "interpreter-core")
        self.assertEqual(roles.get("stdlib"), "stdlib-modules")
        self.assertEqual(roles.get("common"), "concurrency-substrate")
        self.assertEqual(roles.get("derive-impl"), "proc-macro-impl")
        self.assertEqual(roles.get("capi"), "c-abi-shim")
        self.assertIn("vm", d["in_scope_crates"])

    def test_members_dot_idiom_does_not_crash(self) -> None:
        # The `.` member is normalised to the workspace root; Path.glob(".")
        # would otherwise raise on some Python versions.
        with TempRustPythonWorkspace({"crates/vm/src/lib.rs": ""}) as ws:
            d = discover_rustpy.discover(str(ws.root))
        self.assertTrue(d["is_rustpython"])

    def test_subpath_anchors_project_root_at_workspace(self) -> None:
        files = {"crates/vm/src/builtins/dict.rs": "pub fn g() {}\n"}
        with TempRustPythonWorkspace(files) as ws:
            sub = ws.root / "crates" / "vm" / "src"
            d = discover_rustpy.discover(str(sub))
        self.assertEqual(Path(d["project_root"]), ws.root)
        self.assertEqual(Path(d["scan_root"]), sub)
        self.assertTrue(d["is_rustpython"])

    def test_package_name_fallback(self) -> None:
        # Root package name `rustpython` classifies even without a vm member.
        with TempRustPythonWorkspace(
            {"src/main.rs": ""}, member_crates=("common",)
        ) as ws:
            d = discover_rustpy.discover(str(ws.root))
        self.assertTrue(d["is_rustpython"])
        self.assertEqual(d["detection_method"], "package_name_rustpython")

    def test_non_rustpython_workspace_not_in_scope(self) -> None:
        with TempRustPythonWorkspace(
            {"crates/foo/src/lib.rs": ""},
            member_crates=("foo",),
            root_package="some-other-tool",
        ) as ws:
            d = discover_rustpy.discover(str(ws.root))
        self.assertFalse(d["is_rustpython"])

    def test_embedder_out_of_scope(self) -> None:
        # A single crate that depends on rustpython-vm is detected but out of
        # scope (this toolkit reviews the interpreter, not embedders).
        cargo = (
            '[package]\nname = "embedder"\nversion = "0.1.0"\n'
            '[dependencies]\nrustpython-vm = "0.5"\n'
        )
        with TempRustPythonWorkspace(
            {"Cargo.toml": cargo, "src/main.rs": "use rustpython_vm;\n"},
            write_workspace=False,
        ) as ws:
            d = discover_rustpy.discover(str(ws.root))
        self.assertTrue(d["is_rustpython"])
        self.assertTrue(d["out_of_scope"])
        self.assertEqual(d["detection_method"], "embedder_dependency")

    def test_build_report_is_rustpython_flavoured(self) -> None:
        with TempRustPythonWorkspace({"crates/vm/src/lib.rs": ""}) as ws:
            d = discover_rustpy.discover(str(ws.root))
        rep = discover_rustpy.build_rustpy_report(d, [], functions_analyzed=3)
        ci = rep["crate_info"]
        self.assertEqual(ci["runtime"], "rustpython")
        self.assertEqual(ci["version"], "0.5.0")
        self.assertTrue(ci["threading_feature"])
        # Must NOT carry the PyO3 extension shape.
        self.assertNotIn("pyo3_version", ci)
        self.assertNotIn("module_name", ci)
        self.assertEqual(rep["functions_analyzed"], 3)


if __name__ == "__main__":
    unittest.main()
