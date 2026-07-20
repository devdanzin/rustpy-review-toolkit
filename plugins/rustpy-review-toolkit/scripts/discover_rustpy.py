#!/usr/bin/env python3
"""Detect the RustPython interpreter workspace and resolve its review profile.

RustPython (https://github.com/RustPython/RustPython) is a Python interpreter
written in Rust. This toolkit reviews *RustPython's own source* — the runtime,
not extensions built with it — so discovery answers a different question than
the sibling ``discover_rust_ext.py``: "is this the RustPython workspace, and
which member crates are in review scope?"

The RustPython repo root is BOTH a ``[package]`` (``name = "rustpython"``, the
CLI binary) AND a ``[workspace]`` whose members are ``[".", "crates/*"]``. The
``"."`` member is the ``Path.glob(".")`` idiom that raises ``IndexError`` on
some Python versions — normalised to the workspace root here (the same defect
fixed in ``discover_pyo3.py``).

Detection cascade (first match wins):
  1. A workspace whose members contain a ``rustpython-vm`` crate (the VM), or
     whose root package is ``rustpython`` — the canonical case.
  2. A single crate that depends on ``rustpython-vm`` / uses ``rustpython_vm``
     in source — an embedder or out-of-tree crate; detected, reported, but
     flagged out of scope (this toolkit reviews the interpreter itself).
  3. Fallback: any ``.rs`` file that references ``rustpython_vm``.

Outputs a JSON description to stdout. TOML parsing + source-text heuristics
only (no tree-sitter). Also exposes ``build_rustpy_report`` — a RustPython-
flavoured report envelope so scanners don't emit the PyO3-shaped ``crate_info``
that ``scan_common.build_report`` (kept verbatim, never forked) would produce.

Usage:
    python discover_rustpy.py [path]
"""

import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_common import discover_rust_files, find_project_root  # noqa: E402


# Reference to ``rustpython-vm`` (dep name) or ``rustpython_vm`` (use path).
_USES_RUSTPYTHON_RE = re.compile(
    r"\buse\s+rustpython_vm\b|\brustpython_vm\s*::|extern\s+crate\s+rustpython_vm\b"
)

# Per-crate-directory review role. Keyed on the directory basename under
# ``crates/`` (which matches the ``rustpython-<dir>`` crate name for all but
# ``wasm`` -> ``rustpython_wasm``). Roles drive the per-crate emphasis hints
# downstream agents consult.
_CRATE_ROLES: dict[str, str] = {
    "vm": "interpreter-core",
    "stdlib": "stdlib-modules",
    "common": "concurrency-substrate",
    "derive": "proc-macro",
    "derive-impl": "proc-macro-impl",
    "capi": "c-abi-shim",
    "compiler": "compiler",
    "compiler-core": "compiler",
    "compiler-source": "compiler",
    "codegen": "compiler",
    "literal": "support",
    "sre_engine": "support",
    "unicode": "support",
    "wtf8": "support",
    "pylib": "support",
    "jit": "jit",
    "wasm": "frontend",
    "doc": "support",
    "host_env": "support",
    "venvlauncher": "support",
}

# Which member crates are in v0.1 review scope, and why. The runtime-soundness
# agents (panic-site, unsafe-soundness, gc-traverse) target the interpreter
# core and the stdlib; the proc-macro crates are read by the internals mapper.
_IN_SCOPE_ROLES = frozenset(
    {
        "interpreter-core",
        "stdlib-modules",
        "concurrency-substrate",
        "proc-macro-impl",
        "c-abi-shim",
    }
)

# Per-role hint telling downstream agents where to spend attention. Consumed by
# the internals mapper and surfaced in the discovery envelope.
_ROLE_EMPHASIS: dict[str, str] = {
    "interpreter-core": (
        "object model (object/), builtins/, types/, frame — primary target for "
        "panic-site, unsafe-soundness, and gc-traverse"
    ),
    "stdlib-modules": (
        "standard-library modules — primary target for panic-site "
        "(Python-reachable .unwrap()/index in protocol/py methods)"
    ),
    "concurrency-substrate": (
        "RefCount / atomic / lock — the threading-feature toggle lives here; "
        "RefCount protocol auditing is a v0.2 loom/TSan research item"
    ),
    "proc-macro-impl": (
        "#[pyclass] / #[pymethod] / Traverse derive wiring — read by the "
        "internals mapper to attribute Rust sites to Python names and by "
        "gc-traverse to model the HAS_TRAVERSE opt-in gap"
    ),
    "c-abi-shim": (
        'extern "C" C-ABI surface with no catch_unwind — panic-boundary '
        "auditing is a v0.2 item"
    ),
}


def _load_toml(path: Path) -> dict:
    """Parse a TOML file, returning {} on any error."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _safe_read(path: Path) -> str:
    """Read a file as text, returning '' on error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rel(path: Path, root: Path) -> str:
    """Path relative to root if possible, else the absolute path."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _resolve_workspace_root(start: Path) -> Path | None:
    """Climb from ``start`` to the nearest ancestor Cargo.toml with a
    ``[workspace]`` table. Returns the workspace directory, or ``None``.

    ``start`` itself is considered first (RustPython's repo root is the
    workspace root and a common scan target).
    """
    cur = start if start.is_dir() else start.parent
    for _ in range(25):
        data = _load_toml(cur / "Cargo.toml")
        if isinstance(data, dict) and "workspace" in data:
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return None


def _workspace_members(ws_root: Path, ws_data: dict) -> list[Path]:
    """Resolve workspace member globs to directories.

    Normalises the ``"."`` / ``""`` member (RustPython lists ``members =
    [".", "crates/*"]``) to the workspace root — ``Path.glob(".")`` raises
    ``IndexError`` on some Python versions (defect fixed in ``discover_pyo3``).
    ``exclude`` patterns (RustPython excludes ``pymath``) are honoured.
    """
    workspace = ws_data.get("workspace", {}) if isinstance(ws_data, dict) else {}
    members = workspace.get("members", []) if isinstance(workspace, dict) else []
    excludes = workspace.get("exclude", []) if isinstance(workspace, dict) else []
    if not isinstance(members, list):
        return []
    excluded: set[Path] = set()
    if isinstance(excludes, list):
        for pat in excludes:
            if isinstance(pat, str) and pat not in (".", ""):
                for d in ws_root.glob(pat):
                    if d.is_dir():
                        excluded.add(d.resolve())
    out: list[Path] = []
    seen: set[Path] = set()
    for pat in members:
        if not isinstance(pat, str):
            continue
        if pat in (".", ""):
            dirs = [ws_root]
        else:
            dirs = [d for d in sorted(ws_root.glob(pat)) if d.is_dir()]
        for d in dirs:
            rd = d.resolve()
            if rd in excluded or rd in seen:
                continue
            seen.add(rd)
            out.append(d)
    return out


def _crate_name(crate_dir: Path) -> str:
    """The ``package.name`` declared in a crate's Cargo.toml ('' on miss)."""
    data = _load_toml(crate_dir / "Cargo.toml")
    pkg = data.get("package", {}) if isinstance(data, dict) else {}
    name = pkg.get("name", "") if isinstance(pkg, dict) else ""
    return name if isinstance(name, str) else ""


def _workspace_version(ws_data: dict, ws_root: Path) -> tuple[str | None, str | None]:
    """Resolve the workspace version. Returns ``(version, source)``.

    Prefers ``[workspace.package].version`` (RustPython pins 0.5.0 there),
    then a root ``[package].version`` literal, then ``Cargo.lock``.
    """
    workspace = ws_data.get("workspace", {}) if isinstance(ws_data, dict) else {}
    wp = workspace.get("package", {}) if isinstance(workspace, dict) else {}
    v = wp.get("version") if isinstance(wp, dict) else None
    if isinstance(v, str):
        return v, "workspace.package"
    pkg = ws_data.get("package", {}) if isinstance(ws_data, dict) else {}
    pv = pkg.get("version") if isinstance(pkg, dict) else None
    if isinstance(pv, str):
        return pv, "package"
    lock = _load_toml(ws_root / "Cargo.lock")
    packages = lock.get("package", []) if isinstance(lock, dict) else []
    if isinstance(packages, list):
        for p in packages:
            if isinstance(p, dict) and p.get("name") == "rustpython-vm":
                lv = p.get("version")
                if isinstance(lv, str):
                    return lv, "Cargo.lock"
    return None, None


def _threading_feature(ws_data: dict) -> tuple[bool, list[str]]:
    """Detect the ``threading`` cargo feature and whether it is on by default.

    RustPython's root Cargo.toml declares ``threading = [...]`` and lists it in
    ``default``. Under ``threading`` the payloads become ``Send + Sync`` and the
    locks/atomics use real synchronisation; without it they degrade to
    single-threaded ``Cell``/``cell_lock``. Every concurrency-sensitive check is
    parameterised on this toggle, so the profile records it.
    """
    signals: list[str] = []
    default_enabled = False
    features = ws_data.get("features", {}) if isinstance(ws_data, dict) else {}
    if isinstance(features, dict) and "threading" in features:
        signals.append("`threading` feature declared in root Cargo.toml")
        default = features.get("default", [])
        if isinstance(default, list) and "threading" in default:
            signals.append("`threading` is enabled by default")
            default_enabled = True
    # The boolean reflects whether the DEFAULT build is multi-threaded (payloads
    # Send + Sync, real locks/atomics); the "declared" signal is kept for cases
    # where threading exists but is opt-in.
    return default_enabled, signals


def _is_shallow_clone(root: Path) -> bool:
    """True if ``root`` is a shallow git clone (truncated history).

    RustPython has 16k+ commits; a ``git clone --depth N`` hides all temporal
    signal, so ``analyze_history`` would silently under-report. Cheap check:
    a ``.git/shallow`` file (or ``.git`` pointing at one for worktrees).
    """
    git = root / ".git"
    if (git / "shallow").is_file():
        return True
    if git.is_file():  # worktree: .git is a file pointing at the real gitdir
        text = _safe_read(git)
        m = re.match(r"gitdir:\s*(.+)", text.strip())
        if m:
            gitdir = Path(m.group(1))
            if (gitdir / "shallow").is_file():
                return True
    return False


def discover(target: str) -> dict:
    """Discover the RustPython workspace at ``target`` and profile it."""
    target_path = Path(target).resolve()
    ws_root = _resolve_workspace_root(target_path)
    # ``project_root`` anchors on the workspace root when we found one; else on
    # the nearest crate/git marker (so single-crate embedders still resolve).
    root = ws_root or find_project_root(target_path)

    notes: list[str] = []
    is_rustpython = False
    out_of_scope = False
    detection_method = "none"
    crate_roles: dict[str, str] = {}
    in_scope_crates: list[str] = []
    role_emphasis: dict[str, str] = {}
    version: str | None = None
    version_source: str | None = None
    threading = False
    threading_signals: list[str] = []
    root_package_name = ""

    if ws_root is not None:
        ws_data = _load_toml(ws_root / "Cargo.toml")
        root_package_name = (
            ws_data.get("package", {}).get("name", "")
            if isinstance(ws_data.get("package"), dict)
            else ""
        )
        members = _workspace_members(ws_root, ws_data)
        member_names: dict[str, str] = {}  # dir-basename -> crate name
        has_vm = False
        for m in members:
            if m.resolve() == ws_root.resolve():
                continue
            base = m.name
            cname = _crate_name(m)
            member_names[base] = cname
            if cname == "rustpython-vm":
                has_vm = True
            role = _CRATE_ROLES.get(base)
            if role:
                crate_roles[base] = role
                if role in _IN_SCOPE_ROLES:
                    in_scope_crates.append(base)
                    if role in _ROLE_EMPHASIS:
                        role_emphasis[base] = _ROLE_EMPHASIS[role]

        struct_signal = (
            ws_root / "crates" / "vm" / "src" / "object" / "core.rs"
        ).is_file()
        if has_vm or root_package_name == "rustpython":
            is_rustpython = True
            detection_method = (
                "workspace_rustpython_vm" if has_vm else "package_name_rustpython"
            )
        elif struct_signal:
            is_rustpython = True
            detection_method = "structural_object_core"

        version, version_source = _workspace_version(ws_data, ws_root)
        threading, threading_signals = _threading_feature(ws_data)
        if not is_rustpython:
            notes.append(
                "A Cargo workspace was found but it does not look like "
                "RustPython (no `rustpython-vm` member, root package is not "
                "`rustpython`). This toolkit reviews the RustPython interpreter."
            )
    else:
        # No workspace: maybe a single crate that embeds/uses rustpython-vm.
        cargo = _load_toml(root / "Cargo.toml")
        deps = cargo.get("dependencies", {}) if isinstance(cargo, dict) else {}
        uses_dep = isinstance(deps, dict) and "rustpython-vm" in deps
        rs_files_probe = discover_rust_files(root, max_files=200)
        uses_src = any(
            _USES_RUSTPYTHON_RE.search(_safe_read(p)) for p in rs_files_probe
        )
        if uses_dep or uses_src:
            is_rustpython = True
            out_of_scope = True
            detection_method = "embedder_dependency" if uses_dep else "rs_fallback"
            notes.append(
                "This crate depends on / uses `rustpython-vm` but is not the "
                "RustPython workspace itself. This toolkit reviews the "
                "interpreter's own source; an embedder is out of scope."
            )

    rs_files = discover_rust_files(target_path if target_path.is_dir() else root)
    shallow = _is_shallow_clone(root)
    if shallow:
        notes.append(
            "Shallow git clone detected (`.git/shallow`): RustPython has 16k+ "
            "commits, so `analyze_history` will under-report. Run "
            "`git fetch --unshallow` for full temporal signal."
        )

    return {
        "project_root": str(root),
        "scan_root": str(target_path),
        "is_rustpython": is_rustpython,
        "out_of_scope": out_of_scope,
        "detection_method": detection_method,
        "root_package_name": root_package_name,
        "version": version,
        "version_source": version_source,
        "crate_roles": crate_roles,
        "in_scope_crates": sorted(in_scope_crates),
        "role_emphasis": role_emphasis,
        "threading_feature": threading,
        "threading_signals": threading_signals,
        "is_shallow_clone": shallow,
        "source_files": [_rel(p, root) for p in rs_files],
        "total_rs_files": len(rs_files),
        "notes": notes,
    }


def _tool_available(executable: str) -> bool:
    """True if an external executable is resolvable on PATH."""
    return shutil.which(executable) is not None


def build_rustpy_report(
    discovery: dict,
    findings: list[dict],
    *,
    functions_analyzed: int = 0,
) -> dict:
    """Assemble a RustPython-flavoured report envelope.

    Mirrors ``scan_common.build_report`` (which is kept verbatim and never
    forked) but projects RustPython metadata into ``crate_info`` instead of
    the PyO3 extension shape (``pyo3_version``/``module_name`` etc., which are
    meaningless for the interpreter). ``findings`` should already be
    deduplicated by the caller; summary counts are derived here.
    """
    crate_info = {
        "runtime": "rustpython",
        "root_package_name": discovery.get("root_package_name", ""),
        "version": discovery.get("version"),
        "version_source": discovery.get("version_source"),
        "crate_roles": discovery.get("crate_roles", {}),
        "in_scope_crates": discovery.get("in_scope_crates", []),
        "threading_feature": discovery.get("threading_feature", False),
        "is_shallow_clone": discovery.get("is_shallow_clone", False),
        "source_files": discovery.get("source_files", []),
        "tree_sitter_available": True,
        "clippy_available": _tool_available("cargo-clippy"),
        "miri_available": _tool_available("cargo-miri"),
        "cargo_metadata_available": _tool_available("cargo"),
    }
    by_type: dict[str, int] = {}
    by_classification: dict[str, int] = {}
    for finding in findings:
        ftype = str(finding.get("type", ""))
        cls = str(finding.get("classification", ""))
        by_type[ftype] = by_type.get(ftype, 0) + 1
        by_classification[cls] = by_classification.get(cls, 0) + 1
    return {
        "project_root": discovery.get("project_root", ""),
        "scan_root": discovery.get("scan_root", ""),
        "crate_info": crate_info,
        "functions_analyzed": functions_analyzed,
        "findings": findings,
        "summary": {"by_type": by_type, "by_classification": by_classification},
    }


def main() -> None:
    try:
        target = sys.argv[1] if len(sys.argv) > 1 else "."
        result = discover(target)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except Exception as e:  # noqa: BLE001 -- top-level guard, emit JSON error
        json.dump({"error": str(e), "type": type(e).__name__}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
