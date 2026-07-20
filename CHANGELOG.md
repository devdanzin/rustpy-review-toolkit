# Changelog

All notable changes to rustpy-review-toolkit are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

All of the below came from the `exceptions.rs` meta-evaluation — running the full agent panel on one file, grading each agent against ground truth (1 real bug, 14 guarded false positives, a GC-complete file), and feeding the toolkit's own blind spots back into it.

### Changed

- **Panic-site reachability calibration** (`scan_panic_sites.py` + `rustpython_reachability_sources.json`):
  - Added `get_arg(N)` / `.get_arg(` to the `user_index_or_arity` reachability signals. `get_arg(N)` is RustPython's idiomatic arity access; missing it had under-ranked a genuine bug (`ImportError().__reduce__()` aborts the interpreter — `get_arg(0).unwrap()` on empty args, confirmed reproduced) as CONSIDER instead of FIX.
  - Down-rank a fallible-value panic (`args[N]` / `get_arg(N)` / `.unwrap()`) inside a length/arity guard (`if (2..=5).contains(&len)`, `match args.len()`, `if len == 2`, …) from FIX to CONSIDER via a new `_LENGTH_GUARD_RE` over a 16-line lookback. An UNGUARDED arity index (the `_typing._idfunc` / RUSTPY-0005 shape) stays FIX. New `details.length_guarded` flag.
  - **Pure abort-macro stubs → ACCEPTABLE.** A method whose entire body is one `unreachable!(...)` / `unimplemented!(...)` is a RustPython shadow marker (`unreachable!("slot_init is defined")`) that a sibling `slot_*` form overrides — not a data crash. Now classified ACCEPTABLE (`details.stub_body`). `todo!` is excluded (genuinely unimplemented work stays CONSIDER).
  - Net on the whole-tree scan: FIX 95 → 56 (39 guarded false positives reclassified), with **zero loss of confirmed-bug coverage** (all 14 `known_panics.tsv` bugs still surfaced). On `exceptions.rs`: 14 scanner-FIX → 1 (the real bug), + 11 shadow stubs → ACCEPTABLE.

- **`#[pyexception]` payload recognition** (`map_rustpy_internals.py`). `extract_pyclass_payloads` now treats `#[pyexception]` — RustPython's domain-specific exception-payload macro — as a payload-defining attribute, closing the gc-traverse blind spot the mapper and gc agents both surfaced. On `exceptions.rs` the mapper now catalogs **68 payloads (was 1)** and gc-traverse analyzes **68 (was 1)**, still with 0 findings: the transparent-newtype subtypes (`struct PyKeyError(PyLookupError);`) are tuple structs with an empty named-field list → correctly no finding (payload reuse), while a future custom exception payload that adds a ref field and forgets its manual `Traverse` is now caught. Repo-wide, gc-traverse payload coverage rose to 330 with no new false positives. Payloads carry a new `macro` field; the mapper's `classes_without_traverse` orientation list is now filtered to field-bearing payloads.

- **`git-history-analyzer` agent: override `--max-commits` on RustPython.** The vendored `analyze_history.py` defaults to `--max-commits 2000`, which silently truncates a `--days 365/730` window to ~a quarter of the range on RustPython (~2000 commits/7 months) — missing the reference-fix and bug-introduced commits a regression determination needs. The agent now passes `--max-commits 8000` and sanity-checks the returned date range. (The proper clamp-to-window fix belongs upstream in the shared `analyze_history.py`; the vendored copy is not forked.)

### Added

- Found (and reproduced) a new interpreter-abort bug not in the fuzzer catalog: `ImportError().__reduce__()` / `pickle.dumps(ImportError())` panic on `get_arg(0).unwrap()` over an empty args tuple (`exceptions.rs`, `__reduce__`), inherited by `ModuleNotFoundError`. Latent since the `crates/vm` layout was created; a correctly-guarded twin (`OSError.__reduce__`) sits in the same file. CPython returns `(ImportError, ())`.

## [0.1.0] — initial release

The first release: a static, implementer-perspective review toolkit for the RustPython interpreter's own Rust source. Six agents, four commands, tree-sitter-rust-powered, static-first.

### Added

- **Discovery** (`discover_rustpy.py`) — detects the RustPython workspace (the `[package] rustpython` + `[workspace] members = [".", "crates/*"]` idiom), classifies member crates by role, reads the `threading` feature, version, and shallow-clone status, and flags embedders as out of scope. Provides `build_rustpy_report`, a RustPython-flavoured report envelope.
- **Internals mapper** (`map_rustpy_internals.py` + `rustpy-internals-mapper` agent) — the novel primitive. Walks the derive-macro object model and attributes every Rust site to its Python name and **reachability tier** (`py` > `protocol` > `internal`), and catalogs `#[pyclass]` payloads with their traverse option and fields. The single source of truth the scanners import.
- **Flagship panic-site auditor** (`scan_panic_sites.py` + `panic-site-auditor` agent) — finds Python-reachable `.unwrap()`/`.expect()`/`panic!`/`unreachable!`/`unimplemented!`/`todo!`/`args[N]` sites, default-silences the internal tier, and ranks py/protocol sites by the Python-controlled provenance of the failing value (downcast, int-narrowing, user index, repr, warn, TOCTOU). Ported from the fuzzing campaign's `unwrap_scan` seed, plus reachability ranking. Also classifies trait-default method bodies.
- **Unsafe-soundness auditor** (`scan_unsafe_soundness.py` + `unsafe-soundness-auditor` agent) — the crown jewel. Detects cross-method pointer-cast inconsistency (the RUSTPY-0018 `PyAtomicRef` SIGSEGV: one method reads the stored pointer as a different, structurally-related type than its siblings) and handle-type transmute without a `repr(transparent)`/`TransmuteFromObject` guard. Does not flag bare `unsafe` blocks.
- **GC Traverse auditor** (`scan_gc_traverse.py` + `gc-traverse-auditor` agent) — first-class but experimental (0 fuzzer-confirmed instances). Finds `#[pyclass]` payloads that own Python references but declare no traverse, `#[pytraverse(skip)]` on ref-owning fields, and manual traverse bodies missing a field. Uses an intra-file struct-ownership closure and container-vs-scalar ranking. All findings are CONSIDER, never FIX.
- **Reused agents** — `rust-complexity-analyzer` (dispatch-match-aware) and `git-history-analyzer` (RustPython bug lexicon: qsbr/toctou/stop-the-world/pymutex/traverse/refcount).
- **Known-issues regression** (`check_known_issues.py` + `known-issues` command) — the signature command. Drift-tolerantly cross-references the fuzzer-confirmed panic catalog (`known_panics.tsv`, 14 Class A/B bugs) against a fresh scan, reporting each as present / line-drifted / absent.
- **Commands** — `explore` (phased full review), `health` (scored dashboard), `hotspots` (ranked functions), `known-issues`.
- **Data** — `rustpython_protocol_traits.json`, `rustpython_derive_attrs.json`, `rustpython_reachability_sources.json`, `gc_managed_types.json`, `known_panics.tsv`.
- **Chassis** — vendored verbatim from rust-ext-review-toolkit v0.2.0 (`rust_ts_utils.py`, `scan_common.py`, `measure_rust_complexity.py`, `analyze_history.py`, `run_external_tools.py`), with `build_call_graph`/`transitive_calls_to` appended to `rust_ts_utils.py`.
- **Design document** (`rustpy-review-toolkit-design.md`) — the authoritative spec, including the two-input merit assessment (fuzzing report vs. static experiment), the surface catalogue (Classes A–J + Traverse), and the deferred v0.2+ roadmap.
- Tests: 51 unittest cases across discovery, the mapper, and all four scanners, with a `TempRustPythonWorkspace` fixture.

### Notes

- **Static-first.** The CPython differential oracle and the thread-safety / debug-format / capi-panic-boundary / eager-collect / recursion-guard / uninit-object / ctypes agents, plus the `RefCount` loom/TSan research, are deferred to v0.2+ and documented in the design.
- RustPython's object model is under active upstream churn; `known_panics.tsv` line anchors were captured at one checkout and the `known-issues` command is drift-tolerant by design.
