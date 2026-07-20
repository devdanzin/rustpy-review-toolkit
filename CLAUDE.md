# CLAUDE.md — rustpy-review-toolkit development guide

## Project overview
rustpy-review-toolkit is a [Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin for reviewing the **RustPython interpreter itself** — the Python runtime written in Rust, not extensions built with it, and **not PyO3**. It finds Python-reachable panic sites in the VM, unsafe-soundness bugs in the object model (the `PyAtomicRef` cross-method cast-inconsistency / handle-transmute class), and GC `Traverse`-completeness gaps in the cycle collector.

**The load-bearing idea.** RustPython shares PyO3's vocabulary (`PyRef`, `PyResult`, `#[pyclass]`, `.downcast()`) but not its semantics — the PyO3/rust-ext toolkits mis-fire on it with name-collision false positives. Every check here is built from RustPython's own object model. The disambiguator is the **reachability tier** (`py` > `protocol` > `internal`): the internals mapper assigns it, and the panic-site auditor uses it to separate a Python-triggerable crash from an internal invariant.

Part of a family of review toolkits (see README). The closest relatives are **cpython-review-toolkit** (a Python runtime, in Rust instead of C) and **ft-review-toolkit** (concurrency) — *not* the PyO3 toolkits.

## Design document
`rustpy-review-toolkit-design.md` is the authoritative spec — the two-input merit assessment (fuzzing report vs. static experiment), the RustPython architecture primer, the surface catalogue (Classes A–J + Traverse), the component specs, the JSON envelope + FIX/CONSIDER/POLICY/ACCEPTABLE classification, and the deferred v0.2+ roadmap.

## Prerequisites
- Python 3.12 (do NOT use a Python 3.14 debug build — it crashes mypy)
- `tree-sitter` and `tree-sitter-rust`: `pip install tree-sitter tree-sitter-rust`
- Optional: `cargo clippy` / `cargo miri` / `cargo expand` / `cargo metadata` (external-tool cross-referencing)
- A RustPython checkout to review (the user provides the path; nothing is bundled)

## Dev commands
```bash
# Activate the project venv (python3.12)
source ~/venvs/rustpy-review-toolkit/bin/activate

# Run all tests (tests/ is not a package, so use discover)
python -m unittest discover tests -v

# Run a specific test
python -m unittest discover tests -p test_scan_panic_sites.py -v

# Run a single scanner standalone (all output JSON to stdout)
python plugins/rustpy-review-toolkit/scripts/discover_rustpy.py ~/projects/RustPython
python plugins/rustpy-review-toolkit/scripts/scan_panic_sites.py ~/projects/RustPython/crates/vm/src
python plugins/rustpy-review-toolkit/scripts/scan_panic_sites.py --include-internal <path>
python plugins/rustpy-review-toolkit/scripts/check_known_issues.py ~/projects/RustPython

# Lint and type
ruff format <changed-files>
ruff check <changed-files>
mypy plugins/rustpy-review-toolkit/scripts/
```

## Code style
- Python 3.12 (`X | Y` unions, `frozenset[str]`, etc.)
- Double quotes; type hints on all signatures; docstrings on public functions
- Tests use `unittest` — never pytest
- ruff-formatted (default line length 88), mypy-clean

## Project structure
A Claude Code plugin, not a pip package.

```
rustpy-review-toolkit/
├── CLAUDE.md / README.md / CHANGELOG.md / LICENSE
├── rustpy-review-toolkit-design.md      # authoritative spec
├── WORKING_WITH_MAINTAINERS.md          # vendored from rust-ext
├── docs/writing-maintainer-facing-reports.md  # vendored from rust-ext
├── .claude-plugin/                      # marketplace.json + plugin.json
├── plugins/rustpy-review-toolkit/
│   ├── .claude-plugin/plugin.json
│   ├── agents/    # 6 agent prompts
│   ├── commands/  # explore, health, hotspots, known-issues
│   ├── scripts/   # 12 scripts (5 vendored chassis + 7 local)
│   └── data/      # 5 data files
└── tests/         # unittest + helpers.py (TempRustPythonWorkspace)
```

## Architecture
RustPython is a Cargo workspace whose root is simultaneously a `[package]` (the CLI) and a `[workspace]` (`members = [".", "crates/*"]`). `discover_rustpy.py` resolves the workspace root, classifies member crates (interpreter-core / stdlib-modules / concurrency-substrate / proc-macro-impl / c-abi-shim / …), and reads the `threading` feature and version.

**The classification engine is the keystone.** `map_rustpy_internals.py` exposes `classify_functions` (py/protocol/internal tiers) and `extract_pyclass_payloads` (traverse option + fields). These are the **single source of truth** — `scan_panic_sites.py` and `scan_gc_traverse.py` import them so the classification is defined exactly once. Ported from the fuzzing seed's `classify_method`.

**Script calling convention:** every analysis script exposes `analyze(target, *, max_files=0) -> dict` and a `main()` outputting JSON to stdout via `parse_common_args()`. Exception: `analyze_history.py` takes `argv` (family convention; do not normalize). `scan_panic_sites.analyze` and its `main` also accept `include_internal`.

## Adding a new analysis script
1. Create `plugins/rustpy-review-toolkit/scripts/scan_<newcheck>.py`.
2. Import from `map_rustpy_internals` (for tier/payload classification), `rust_ts_utils`, `scan_common`, and `discover_rustpy` (`build_rustpy_report`).
3. Implement `analyze(target, *, max_files=0) -> dict` per the JSON envelope; use `build_rustpy_report` (NOT `scan_common.build_report` — that emits the PyO3 crate_info shape).
4. Add `main()` using `parse_common_args()`.
5. Create `tests/test_scan_<newcheck>.py`: true positive (from a confirmed finding), true negative, ≥1 RustPython-specific edge case, using `TempRustPythonWorkspace`.
6. Create the matching `agents/<newcheck>-auditor.md` with YAML frontmatter and the Preflight/Key-Concepts/Analysis-Phases structure.
7. Add the agent to the right phase group in `commands/explore.md`.
8. Update CHANGELOG.md.

## Gotchas (RustPython-specific)
- **`unsafe` is the norm.** The object model is ~30% unsafe; never flag bare `unsafe` blocks. Only the two specific shapes (cast inconsistency, unguarded handle transmute) surface.
- **The reachability tier is everything.** `internal`-tier panics are default-silenced. RustPython's `PyRef`/`PyResult`/`#[pyclass]` are NOT PyO3's — never apply PyO3 Send/Sync semantics.
- **`.unwrap()` on a `PyResult` IS a bug here** (it discards a Python exception and aborts the interpreter) — unlike a PyO3 extension where PyO3 catches it.
- **`members = ["."]` idiom.** RustPython's root is both package and workspace; `Path.glob(".")` raises `IndexError` on some Python versions — `_workspace_members` normalizes `"."` to the workspace root.
- **The safe `#[pytraverse(skip)]`.** A skip on `counter: PyRwLock<BigInt>` (enumerate) is correct — `BigInt` owns no Python ref. The gc-traverse ref-ownership check must distinguish it from `iterable: PyIter`.
- **GC findings never exceed CONSIDER.** The class is real but unvalidated (0 fuzzer-confirmed instances); mark it experimental.
- **Line drift.** The object model churns upstream; `known_panics.tsv` anchors were captured at one checkout. `check_known_issues.py` is drift-tolerant (present / line_drifted / absent). `known_panics.tsv` is the panic subset (Class A/B) — Class C bugs like RUSTPY-0018 (SIGSEGV) are caught by the unsafe agent, not this catalog.
- **Parse the source bytes once**, slice on `node.start_byte`/`node.end_byte`. Never re-read a file in a helper.
- **Never compare tree-sitter nodes with `is`** — use `node_a.id == node_b.id`.
- **`analyze_history.py` takes `argv`**, not `(target, max_files)`. Do not normalize.

## Vendoring model (never fork the shared files)
The five chassis scripts (`rust_ts_utils.py`, `scan_common.py`, `measure_rust_complexity.py`, `analyze_history.py`, `run_external_tools.py`) are vendored **verbatim** from rust-ext-review-toolkit and must stay byte-identical. If a shared primitive needs changing, change it upstream in rust-ext and sync forward — do NOT edit the vendored copy. The only allowed local seams:
- `measure_rust_complexity.py`'s `discover_rustpy` import (a try/except fallback, mirroring pyo3-review-toolkit).
- `build_call_graph`/`transitive_calls_to` appended to `rust_ts_utils.py` (additive, identical to pyo3's copy).

RustPython-specific report shaping lives in `discover_rustpy.build_rustpy_report`, keeping `scan_common.build_report` untouched. The history bug-lexicon retuning lives in the `git-history-analyzer` **agent** (Phase-2 grep instructions), not in the vendored `analyze_history.py`.

## Sibling synchronization
- **Code-driven (rust-ext-review-toolkit — quarterly):** re-sync the five chassis scripts and `docs/writing-maintainer-facing-reports.md` + `WORKING_WITH_MAINTAINERS.md`. Re-append the call-graph primitives if `rust_ts_utils.py` is refreshed.
- **Locally maintained (RustPython releases):** refresh the five `data/` files and re-import `known_panics.tsv` from the findings repo; update `RUSTPYTHON_FIXTURE_COMMIT` in `tests/helpers.py`.

## Workflow
- Run the heavy multi-agent commands (`explore`, `health`) at phase/slice boundaries, not after every change.
- Commit only when asked; branch off `main` first if needed. `reports/` is gitignored.
