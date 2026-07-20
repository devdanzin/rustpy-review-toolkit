# rustpy-review-toolkit

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin that statically reviews the **[RustPython](https://github.com/RustPython/RustPython) interpreter's own Rust source** for soundness and crash bugs — from the runtime-implementer's perspective.

RustPython is a Python interpreter written in Rust. This toolkit reviews *the interpreter itself*, not extensions built with it, and **not PyO3**. RustPython shares PyO3's vocabulary (`PyRef`, `PyResult`, `#[pyclass]`) but has its own object model, cycle-collecting GC, bit-packed `RefCount`, and `threading`-feature toggle — so every check is RustPython-native, not transplanted from a PyO3 toolkit.

## What it finds

- **Python-reachable panics** (the flagship) — `.unwrap()` / `.expect()` / `panic!` / index / arity sites in the VM, tiered by reachability (`py` > `protocol` > `internal`) so a crash a Python program can trigger surfaces while internal invariants stay quiet. This is RustPython's dominant confirmed crash class.
- **Unsafe soundness** (the crown jewel) — cross-method pointer-cast inconsistency in the object model (the `PyAtomicRef` SIGSEGV shape) and handle-type transmute without a `repr(transparent)` / `TransmuteFromObject` guard.
- **GC Traverse-completeness** (first-class, experimental) — `#[pyclass]` payloads that own Python references but declare no `traverse`, `#[pytraverse(skip)]` on ref-owning fields, and manual `traverse` bodies that miss a field.
- **Complexity** and **git history** — reused, RustPython-calibrated.

Scanners find *candidates* (deliberately high recall); the agents confirm or dismiss each by reading the real code and judging Python-reachability.

## Install

```
claude plugin marketplace add devdanzin/rustpy-review-toolkit
claude plugin install rustpy-review-toolkit@rustpy-review-toolkit
```

## Commands

| Command | What it does |
|---|---|
| `/rustpy-review-toolkit:explore [scope] [aspects]` | Full phased review: discovery → preflight orientation → panic-site + unsafe + traverse → complexity + history → synthesis |
| `/rustpy-review-toolkit:health [scope]` | Quick scored 1–10 dashboard across every dimension |
| `/rustpy-review-toolkit:hotspots [scope]` | Rank the riskiest functions (panic + unsafe + complexity) |
| `/rustpy-review-toolkit:known-issues [scope]` | Cross-reference the fuzzer-confirmed panic catalog against a fresh scan — which reproduced crashes are still present |

Point them at a RustPython checkout:

```
/rustpy-review-toolkit:explore ~/projects/RustPython
/rustpy-review-toolkit:known-issues ~/projects/RustPython/crates/vm
```

## Agents

| Agent | Focus |
|---|---|
| `rustpy-internals-mapper` | preflight — indexes the macro object model into reachability tiers + a payload catalog |
| `panic-site-auditor` | **flagship** — Python-reachable panics, ranked by provenance |
| `unsafe-soundness-auditor` | **crown jewel** — object-model cast inconsistency + handle transmute |
| `gc-traverse-auditor` | first-class, experimental — cycle-collector completeness |
| `thread-safety-auditor` | Class F — non-Sync interior mutability on a shared `#[pyclass]` payload force-marked Sync |
| `debug-format-auditor` | Class I — `{:?}` on a Python object reaching the unsound `PyAtomicRef` Debug (severity-gated) |
| `capi-panic-boundary` | panics + unguarded pointer derefs across the C ABI in `crates/capi` (experimental) |
| `ctypes-ffi-auditor` | Class H — int→pointer narrowing in `_ctypes` |
| `recursion-guard-auditor` | Class D — unguarded protocol recursion → native stack overflow |
| `eager-collect-parity` | Class G — eager iterable binding where CPython streams (needs a CPython differential) |
| `uninitialized-object-auditor` | Class E — a payload slot on a `T.__new__(T)` instance |
| `rust-complexity-analyzer` | complexity hotspots (dispatch-match aware) |
| `git-history-analyzer` | similar-unfixed-bug detection, RustPython bug lexicon |

## How it works

Tree-sitter-rust parses RustPython's source; the internals mapper attributes every Rust site to its Python name and reachability tier; the scanners overlay their pattern checks on that classification. The design is **static-first**: the v0.2 class-expansion agents that need a CPython/concurrency differential (thread-safety, ctypes, eager-collect, recursion, uninit) encode the fuzzer's verified SAFE lists as data and leave the differential to agent triage. An automated differential oracle and `RefCount` loom/TSan research remain deferred (see [`rustpy-review-toolkit-design.md`](rustpy-review-toolkit-design.md)).

## Family of toolkits

- [code-review-toolkit](https://github.com/devdanzin/code-review-toolkit) — Python source
- [cpython-review-toolkit](https://github.com/devdanzin/cpython-review-toolkit) — CPython C
- [cext-review-toolkit](https://github.com/devdanzin/cext-review-toolkit) — C extensions
- [rust-ext-review-toolkit](https://github.com/devdanzin/rust-ext-review-toolkit) — Rust/PyO3 extensions
- [pyo3-review-toolkit](https://github.com/devdanzin/pyo3-review-toolkit) — the PyO3 framework
- **rustpy-review-toolkit** — the RustPython interpreter (this project)

The closest relatives are cpython-review-toolkit (a Python runtime, in Rust instead of C) and ft-review-toolkit (concurrency) — **not** the PyO3 toolkits.

## License

MIT
