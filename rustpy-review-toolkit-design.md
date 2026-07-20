# rustpy-review-toolkit — design document

**Status:** v0.1 (initial release). Authoritative spec for the toolkit's scope, architecture, classification, and roadmap.

## 1. Project identity

`rustpy-review-toolkit` is a [Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin that statically reviews the **RustPython interpreter's own Rust source** for soundness and crash bugs. RustPython (<https://github.com/RustPython/RustPython>) is a Python interpreter written in Rust; this toolkit reviews the *runtime itself*, from the implementer's perspective — not extensions built with it, and not PyO3.

### Relationship to the sibling toolkits

This is a member of a family of `-review-toolkit` plugins, but it is **not a PyO3 sibling**:

| Toolkit | Reviews |
|---|---|
| [code-review-toolkit](https://github.com/devdanzin/code-review-toolkit) | Python source |
| [cpython-review-toolkit](https://github.com/devdanzin/cpython-review-toolkit) | CPython runtime C code |
| [cext-review-toolkit](https://github.com/devdanzin/cext-review-toolkit) | C extensions |
| [rust-ext-review-toolkit](https://github.com/devdanzin/rust-ext-review-toolkit) | Rust/PyO3 extensions (consumer side) |
| [pyo3-review-toolkit](https://github.com/devdanzin/pyo3-review-toolkit) | the PyO3 framework itself (implementer side) |
| **rustpy-review-toolkit** | **the RustPython interpreter itself** (this project) |

The closest conceptual relatives are **cpython-review-toolkit** (reviewing a Python runtime, just implemented in Rust instead of C) and **ft-review-toolkit** (concurrency), *not* the PyO3 toolkits.

### Why a native toolkit was needed

RustPython shares PyO3's *vocabulary* — `PyRef`, `PyResult`, `#[pyclass]`, `.downcast()` — but not its *semantics*. A cross-application experiment (running the pyo3 and rust-ext toolkits against RustPython) established a **transfer gradient**:

- The **implementer scanner** (pyo3-review-toolkit) keyed on `unsafe { ffi::<CPython C-API> }` — a substrate RustPython lacks — and produced clean true-negatives (nothing to match).
- The **consumer scanners** (rust-ext-review-toolkit) keyed on PyO3-consumer idioms that RustPython independently uses under the same names, and mis-fired with **name-collision false positives**: 4 `non_send_field` findings classified FIX on RustPython's own `#[pyclass]` types, 269 `renamed_api` on RustPython's own `.downcast()`. Agent triage did **not** rescue them, because the agent instructions themselves encode PyO3 semantics.

The lesson: RustPython's real bug classes are **native**, not transplantable. This toolkit's checks are built from RustPython's own object model.

## 2. The two research inputs and their merit assessment

Two inputs fed the design; both were assessed on merit, not treated as authoritative.

1. **A static cross-application experiment** — concluded the crown jewels were GC `Traverse`-completeness and the `RefCount` atomic protocol.
2. **A fuzzing defect analysis** — a `fusil` + CPython-differential campaign. 24 confirmed findings across 10 classes (A–J), a buildable static seed (`unwrap_scan`), and a proposed agent panel. Written explicitly as design advocacy, to be tested.

The two inputs *disagree*; reconciling them with the code evidence is the design's foundation.

| Surface | Fuzzing report | Static experiment | Verdict |
|---|---|---|---|
| **Python-reachable `unwrap`/index panic (Classes A+B)** | Flagship, 12/24 | *Missed it* | **ACCEPT as flagship.** The report's biggest contribution; corrects the experiment's blind spot. |
| **Unsafe layout-transmute / pointer-cast inconsistency (Class C, `PyAtomicRef` SIGSEGV)** | Highest severity | Independently flagged | **ACCEPT, doubly-confirmed crown jewel.** |
| **GC `Traverse`-completeness** | *Never examined* | Headline crown jewel | **ACCEPT as first-class, honestly marked** — real surface, 0 fuzzer-confirmed instances. Covers the fuzzer's blind spot. |
| **`RefCount` atomic protocol** | "don't build a refcount-auditor" | 2nd crown jewel | **REJECT for v0.1** (over-weighted by the experiment) → v0.2 loom/TSan research. |
| Refcount-balance / GIL-pairing / NULL-in-internals auditors | "empty — don't build" | (agreed) | **REJECT** — `PyRc = Arc`, safe Rust. *Exception:* unguarded raw-ptr deref in `crates/capi` → v0.2. |
| Thread-safety (Class F: `RefCell`/`Cell` on non-`unsendable` `#[pyclass]`) | Real, needs concurrency differential | name-collision FP | **ACCEPT, v0.2** (static candidates; confirmation is dynamic). |
| Debug-`{:?}`-format (Class I) | Cheap/precise | — | **ACCEPT, v0.2**, severity-gated on the unsound `Debug` still existing. |
| Eager-collect-parity (G), recursion-guard (D), uninit-object (E), ctypes-ffi (H) | Proposed agents | — | **ACCEPT, v0.2+** (interprocedural / CPython-oracle). |
| CPython differential oracle | "turns a panic into a bug" | — | **ACCEPT as v0.2** (v0.1 is static-first). |

**Corrections carried (do not repeat):** the report's headline counts are wrong — the actual `risky_sites.tsv` is 971 sites (686 internal / 126 protocol / 159 py), 690 `.unwrap()` / 126 `.expect(`, across 64 module labels. File:line anchors drift between checkouts; pin citations to the reviewed commit.

## 3. RustPython architecture primer

The toolkit's checks are grounded in these internals (anchors against RustPython `main`; the object model is under active upstream churn — verify before citing).

### 3.1 The object model (`crates/vm/src/object/`)

`#[repr(transparent)]` handle triad: `PyObjectRef` = `NonNull<PyObject>`, `PyObject` = `PyInner<Erased>`, `Py<T>` = `PyInner<T>`, `PyRef<T>` = `NonNull<Py<T>>` (Drop → `ref_count.dec()`), `PyStackRef` = a low-bit-tagged `NonZeroUsize`. `PyResult<T = PyObjectRef> = Result<T, PyBaseExceptionRef>`. `PyAtomicRef<T>` = `PyAtomic<*mut u8>` + `PhantomData<T>` storing a leaked `Py<T>` — the RUSTPY-0018 SIGSEGV lives in its `Debug` impl.

### 3.2 Derive macros and protocol traits (`crates/derive-impl/src/`)

A Python type is a `#[pyclass]` struct/enum (identity + GC on the struct attr) plus an impl block whose `#[pyclass(with(Trait, …))]` composes protocol slots from trait impls. Exposed methods carry `#[pymethod]` / `#[pygetset]` / `#[pyslot]` / `#[pystaticmethod]` / `#[pyclassmethod]`; free functions carry `#[pyfunction]`; the Python name is `name = "…"` or the ident (or `__ident__` under `#[pymethod(magic)]`). The **protocol traits** (`Representable`, `Hashable`, `Comparable`, `AsMapping`, `IterNext`, `Callable`, `Constructor`, …) are the `with(Trait)` slot surface — Python-reachable without any per-method attribute.

### 3.3 The cycle collector (`crates/vm/src/object/traverse.rs`)

`unsafe trait Traverse` — visit every owned `PyObjectRef`/`PyRef` **at most once** (a miss leaks, a repeat can panic/deadlock the collector); never clone a ref in `traverse`; lock impls use fallible `try_read`/`try_lock` + skip-on-fail. A `#[pyclass]` opts in via `traverse` (auto `#[derive(Traverse)]`), `traverse = "manual"` (hand-written impl), or nothing (`HAS_TRAVERSE = false` — invisible to the collector). `#[pytraverse(skip)]` drops a field from the derive.

### 3.4 RefCount, threading toggle, capi, error model

- **`RefCount`** (`crates/common/src/refcount.rs`) — a bit-packed `usize` (destructed/published/leaked | weak | strong) with a `dec` Release + `fence(Acquire)`-on-last protocol. **All-safe atomics**, zero `unsafe` — its soundness surface needs loom/TSan, not a static scanner (v0.2).
- **`threading` feature** — under it, payloads are `Send + Sync` (`PyThreadingConstraint`) and locks/atomics use real synchronisation; without it they degrade to `Cell`/`cell_lock`. On by default. Every concurrency check is parameterised on this toggle.
- **`crates/capi`** — ~379 `pub extern "C" fn` with **no `catch_unwind` anywhere**; a `panic!` unwinds across the C ABI = UB (v0.2 panic-boundary agent).
- **`vm.` error model** — `#[pymethod] fn f(&self, …, vm: &VirtualMachine) -> PyResult<T>`; errors via `vm.new_*_error(...)` and `?`. The defect shape: unwrapping a `vm`-fallible call instead of propagating it.

## 4. Surface catalogue

Each row: mechanism, whether it is statically checkable, and its version status.

| Class | Mechanism | Static? | Status |
|---|---|---|---|
| **A. Panic on Python-reachable `unwrap`/`expect`** | fallible value from Python input, unwrapped | yes (tier + provenance) | **v0.1 flagship** |
| **B. Index / arity OOB** | `args[N]`, user index out of bounds | yes | **v0.1 flagship** |
| **C. Unsafe layout-transmute / cast inconsistency** | stored raw pointer read as inconsistent types (0018) | yes (cross-method cast) | **v0.1 crown jewel** |
| **Traverse. GC completeness** | ref-owning payload with no/incomplete traverse | yes (experimental) | **v0.1 first-class, unvalidated** |
| D. Recursion-guard bypass | native recursion without the Python guard | interprocedural | v0.2+ |
| E. Uninitialized-object access | `assume_init` on a partial object | needs dataflow | v0.2+ |
| F. Thread-safety (`RefCell`/`Cell` on shared pyclass) | non-`unsendable` interior mutability | static candidates, dynamic confirm | v0.2 |
| G. Eager-collect parity | unbounded native collect vs CPython lazy | needs CPython oracle | v0.2+ |
| H. ctypes / FFI | pointer/arg mishandling in `_ctypes` | narrow | v0.2+ |
| I. Debug-`{:?}`-format | unsound `Debug` reachable from Python | cheap, severity-gated | v0.2 |
| J. abort-vs-MemoryError | (report says do NOT report) | — | out of scope |
| RefCount protocol | atomic ordering correctness | needs loom/TSan | v0.2 research |

## 5. Components (v0.1)

### 5.1 Agents (`plugins/rustpy-review-toolkit/agents/`)

| Agent | Role |
|---|---|
| `rustpy-internals-mapper` | preflight; builds the reachability index + payload catalog every downstream agent reads |
| `panic-site-auditor` | **flagship** — Classes A+B, tiered py > protocol > internal |
| `unsafe-soundness-auditor` | **crown jewel** — Class C cast-inconsistency + unguarded handle transmute |
| `gc-traverse-auditor` | first-class, experimental — GC Traverse-completeness |
| `rust-complexity-analyzer` | reused chassis; RustPython calibration (dispatch-match de-weighting) |
| `git-history-analyzer` | reused chassis; RustPython bug lexicon (qsbr/toctou/traverse/…) |

### 5.2 Scanners (`scripts/`, `analyze(target, *, max_files=0) -> dict` + `main()`)

- `discover_rustpy.py` — workspace detection, crate-role classification, `threading`/version/shallow-clone profile, and `build_rustpy_report` (the RustPython report envelope).
- `map_rustpy_internals.py` — the classification engine: `classify_functions` (py/protocol/internal tiers) and `extract_pyclass_payloads`, the **single source of truth** imported by the scanners.
- `scan_panic_sites.py` — the flagship; tier-gated pattern matching + reachability ranking.
- `scan_unsafe_soundness.py` — cross-method cast inconsistency (0018) + unguarded handle transmute.
- `scan_gc_traverse.py` — missing / skip-on-ref / manual-gap traverse checks, with an intra-file struct-ownership closure.
- `check_known_issues.py` — drift-tolerant cross-reference of `known_panics.tsv` against a fresh panic scan (backs the `known-issues` command).
- Vendored chassis: `rust_ts_utils.py`, `scan_common.py`, `measure_rust_complexity.py`, `analyze_history.py`, `run_external_tools.py`.

### 5.3 Data (`data/`)

`rustpython_protocol_traits.json`, `rustpython_derive_attrs.json`, `rustpython_reachability_sources.json`, `gc_managed_types.json`, `known_panics.tsv` (the fuzzer-confirmed panic catalog — Class A/B; Class C bugs like 0018 are caught by the unsafe agent, not this catalog).

### 5.4 Commands (`commands/`)

`explore` (phased full review), `health` (scored dashboard), `hotspots` (panic + unsafe + complexity, ranked by function), `known-issues` (the signature regression command).

## 6. JSON envelope and classification

Every scanner emits the common envelope: `{project_root, scan_root, crate_info, functions_analyzed, findings[], summary}`. Each finding: `{type, file, line, function, category, classification, confidence, description, details}`.

**Classification, calibrated for a Python runtime:**

- **FIX** — a real bug a Python program can trigger: a py/protocol-tier panic on Python-controlled input; a confirmed cross-method cast inconsistency (memory unsafety); a fuzzer-confirmed panic still present.
- **CONSIDER** — worth review but needs judgment: a py/protocol panic whose reachability is unconfirmed; an unguarded handle transmute; **all** gc-traverse findings (experimental).
- **POLICY** — a deliberate, documented invariant the maintainers chose (a "can't happen" `panic!`; a type intentionally not GC-tracked).
- **ACCEPTABLE** — provably fine: an internal-tier panic with no Python-reachable chain; a `repr(transparent)`-sound transmute; a `#[pytraverse(skip)]` on a non-ref-owning field.

**Calibration principles:**
- **`unsafe` is the norm**, not a flag — the unsafe agent fires only on the two specific shapes, never on bare `unsafe` blocks.
- **The reachability tier is the discriminator** — `internal`-tier panics are default-silenced; only `py`/`protocol` surface.
- **GC findings never exceed CONSIDER** in v0.1 — the class is real but unvalidated (0 fuzzer-confirmed instances).

## 7. Deferred roadmap (v0.2+)

CPython **differential oracle** (dynamic harness — "turns a panic into a bug") · **thread-safety-auditor** (Class F) · **debug-format-auditor** (Class I, severity-gated) · **capi-panic-boundary** + capi null-deref · **eager-collect-parity** (Class G) · **recursion-guard** (D) · **uninitialized-object** (E) · **ctypes-ffi** (H) · **`RefCount` protocol** loom/TSan research · GC-traverse validation (drive the collector under a stress harness to confirm the static candidates).

## 8. Vendoring model

The five chassis scripts (`rust_ts_utils.py`, `scan_common.py`, `measure_rust_complexity.py`, `analyze_history.py`, `run_external_tools.py`) are vendored **verbatim** from rust-ext-review-toolkit and must never be forked. New shared primitives go upstream to rust-ext and sync forward; the only local seam is the `discover_rustpy` import in `measure_rust_complexity.py` (a try/except fallback, matching pyo3-review-toolkit). RustPython-specific report shaping lives in `build_rustpy_report` (in `discover_rustpy.py`), keeping the shared `scan_common.build_report` untouched. The call-graph primitives (`build_call_graph` / `transitive_calls_to`) are appended to the vendored `rust_ts_utils.py` identically to pyo3-review-toolkit's copy.
