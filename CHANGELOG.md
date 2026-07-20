# Changelog

All notable changes to rustpy-review-toolkit are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
