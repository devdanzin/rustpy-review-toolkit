"""Test helpers for rustpy-review-toolkit tests.

``import_script`` loads a plugin script as a module (the scripts directory is
not a package). ``TempRustPythonWorkspace`` fabricates a minimal RustPython-
shaped Cargo workspace on disk so discovery and the scanners can be exercised
without the real 472-file tree.

Fixtures derived from real RustPython source are pinned to the tag recorded in
``RUSTPYTHON_FIXTURE_COMMIT`` (see below) — the object model is under active
upstream churn, so line anchors drift.
"""

import importlib.util
import shutil
import tempfile
from pathlib import Path
from types import ModuleType

# RustPython checkout the true-positive fixtures / known_panics.tsv line anchors
# were captured against. ``~/projects/RustPython`` HEAD at authoring time.
RUSTPYTHON_FIXTURE_COMMIT = "3290f287f"

_SCRIPTS_DIR = (
    Path(__file__).resolve().parent.parent
    / "plugins"
    / "rustpy-review-toolkit"
    / "scripts"
)


def import_script(name: str) -> ModuleType:
    """Import a script from the plugin's scripts/ directory as a module.

    The scripts directory is not a Python package; scripts add it to
    ``sys.path`` themselves so they can import their siblings.
    """
    path = _SCRIPTS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load script: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Root manifest: RustPython's repo root is simultaneously a ``[package]``
# (the ``rustpython`` CLI binary) and a ``[workspace]`` whose members are
# ``[".", "crates/*"]``. The ``threading`` feature (on by default) is the
# single lever that makes payloads ``Send + Sync`` and switches the locks /
# atomics to real synchronisation, so discovery reads it.
_ROOT_CARGO_TEMPLATE = """\
[package]
name = "{root_package}"
version = {version_field}
edition = "2024"

[features]
default = [{default_features}]
threading = ["rustpython-vm/threading", "rustpython-stdlib/threading"]
stdlib = []

[workspace]
resolver = "2"
members = [
    ".",
    "crates/*",
]
exclude = ["pymath"]

[workspace.package]
version = "{version}"
edition = "2024"
"""

_MEMBER_CARGO_TEMPLATE = """\
[package]
name = "rustpython-{crate}"
version.workspace = true
edition.workspace = true
"""


class TempRustPythonWorkspace:
    """Create a temporary RustPython-shaped Cargo workspace for testing.

    Usage::

        files = {"crates/vm/src/builtins/foo.rs": rust_code}
        with TempRustPythonWorkspace(files) as ws:
            result = some_script.analyze(str(ws.root))

    A workspace root ``Cargo.toml`` (``[package] name = "rustpython"`` +
    ``[workspace] members = [".", "crates/*"]`` + the ``threading`` feature)
    is generated, plus a minimal ``crates/<name>/Cargo.toml`` for every entry
    in ``member_crates`` so ``discover_rustpy`` sees a ``rustpython-vm`` member
    and classifies crate roles. ``files`` are written verbatim at their given
    relative paths.

    Options:
        files            mapping of relative path -> file content
        member_crates    crate dir names to generate manifests for (must
                         include ``"vm"`` for discovery to classify as
                         RustPython via ``rustpython-vm``)
        version          workspace version string
        threading_default whether ``threading`` is listed in ``default``
        root_package     the root ``[package].name`` (``rustpython`` normally)
        write_workspace  set False to omit the root Cargo.toml entirely
                         (to exercise the non-workspace discovery fallback)
    """

    def __init__(
        self,
        files: dict[str, str],
        *,
        member_crates: tuple[str, ...] = (
            "vm",
            "stdlib",
            "common",
            "derive-impl",
            "capi",
        ),
        version: str = "0.5.0",
        threading_default: bool = True,
        root_package: str = "rustpython",
        write_workspace: bool = True,
    ) -> None:
        self.files = files
        self.member_crates = member_crates
        self.version = version
        self.threading_default = threading_default
        self.root_package = root_package
        self.write_workspace = write_workspace
        self.root: Path = Path()
        self._tmpdir: str | None = None

    def _root_cargo(self) -> str:
        defaults = (
            ['"threading"', '"stdlib"'] if self.threading_default else ['"stdlib"']
        )
        return _ROOT_CARGO_TEMPLATE.format(
            root_package=self.root_package,
            version=self.version,
            version_field="{ workspace = true }",
            default_features=", ".join(defaults),
        )

    def __enter__(self) -> "TempRustPythonWorkspace":
        self._tmpdir = tempfile.mkdtemp(prefix="rustpy_test_")
        root = Path(self._tmpdir)
        self.root = root
        if self.write_workspace:
            (root / "Cargo.toml").write_text(self._root_cargo(), encoding="utf-8")
            for crate in self.member_crates:
                crate_dir = root / "crates" / crate
                crate_dir.mkdir(parents=True, exist_ok=True)
                (crate_dir / "Cargo.toml").write_text(
                    _MEMBER_CARGO_TEMPLATE.format(crate=crate), encoding="utf-8"
                )
        for rel_path, content in self.files.items():
            full = root / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content, encoding="utf-8")
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
