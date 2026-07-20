"""Tests for scan_panic_sites.py — the flagship panic-site auditor."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import TempRustPythonWorkspace, import_script  # noqa: E402

scan = import_script("scan_panic_sites")


def _run(files: dict[str, str], **kw: object) -> dict:
    with TempRustPythonWorkspace(files) as ws:
        return scan.analyze(str(ws.root), **kw)  # type: ignore[arg-type]


class TestPanicSites(unittest.TestCase):
    def test_py_tier_unwrap_with_high_signal_is_fix(self) -> None:
        # A #[pymethod] that downcasts a Python object then unwraps → FIX.
        src = """
impl PyFoo {
    #[pymethod]
    fn convert(&self, obj: PyObjectRef, vm: &VirtualMachine) -> PyResult<()> {
        let n = obj.downcast::<PyInt>().unwrap();
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        fix = [f for f in r["findings"] if f["classification"] == "FIX"]
        self.assertTrue(fix, "expected a FIX for py-tier unwrap on a downcast")
        self.assertEqual(fix[0]["details"]["tier"], "py")
        self.assertIn("downcast_or_coerce", fix[0]["details"]["reachability_signals"])

    def test_protocol_tier_repr_unwrap_is_surfaced(self) -> None:
        # The staticmethod-repr shape (RUSTPY-0009): Representable slot unwraps.
        src = """
impl Representable for PyFoo {
    fn repr_str(&self, vm: &VirtualMachine) -> PyResult<String> {
        let s = self.value.repr(vm).unwrap();
        Ok(s)
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertEqual(f["details"]["tier"], "protocol")
        self.assertIn(f["classification"], ("FIX", "CONSIDER"))

    def test_internal_tier_silenced_by_default(self) -> None:
        src = """
impl PyFoo {
    fn helper(&self) -> u32 {
        self.cache.get().unwrap()
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["panic_scan"]["internal_sites_suppressed"], 1)

    def test_include_internal_reveals_helper(self) -> None:
        src = """
impl PyFoo {
    fn helper(&self) -> u32 {
        self.cache.get().unwrap()
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src}, include_internal=True)
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["findings"][0]["classification"], "ACCEPTABLE")
        self.assertEqual(r["findings"][0]["details"]["tier"], "internal")

    def test_args_index_arity_pattern(self) -> None:
        # The _typing._idfunc shape: indexing args[0] without an arity check.
        src = """
#[pyfunction]
fn idfunc(args: FuncArgs, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
    Ok(args.args[0].clone())
}
"""
        r = _run({"crates/vm/src/stdlib/typing.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "args-index")
        self.assertEqual(f["details"]["tier"], "py")
        self.assertIn("user_index_or_arity", f["details"]["reachability_signals"])

    def test_comment_line_is_skipped(self) -> None:
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self) {
        // this.unwrap() is only in a comment
        let x = 1;
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        self.assertEqual(r["findings"], [])

    def test_explicit_panic_macro_is_consider(self) -> None:
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self) {
        panic!("should not happen");
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "panic")
        self.assertEqual(f["classification"], "CONSIDER")

    def test_weak_invariant_signal_downgrades(self) -> None:
        # A downcast (high signal) but a nearby "// SAFETY:" weak-invariant note
        # → CONSIDER, not FIX.
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self, obj: PyObjectRef) -> PyResult<()> {
        // SAFETY: checked above that obj is always a PyInt
        let n = obj.downcast::<PyInt>().unwrap();
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertTrue(f["details"]["weak_invariant_signal"])
        self.assertEqual(f["classification"], "CONSIDER")


class TestCalibrationFixes(unittest.TestCase):
    """Calibration from the exceptions.rs deep-dive (v0.1.1)."""

    def test_get_arg_unwrap_is_fix(self) -> None:
        # The ImportError.__reduce__ shape (exceptions.rs:1872): get_arg(0) on a
        # possibly-empty args tuple, unwrapped, with no length guard → FIX. The
        # get_arg( token must fire the user_index_or_arity signal.
        src = """
impl PyImportError {
    #[pymethod]
    fn __reduce__(&self, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        Ok(vm.new_tuple((self.get_arg(0).unwrap(),)).into())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertEqual(f["classification"], "FIX")
        self.assertIn("user_index_or_arity", f["details"]["reachability_signals"])
        self.assertFalse(f["details"]["length_guarded"])

    def test_guarded_arity_index_downgraded_to_consider(self) -> None:
        # args[N] inside an `if (2..=5).contains(&len)` guard → CONSIDER, not FIX.
        src = """
impl PyOSError {
    #[pyslot]
    fn slot_init(&self, args: FuncArgs, vm: &VirtualMachine) -> PyResult<()> {
        let len = args.args.len();
        if (2..=5).contains(&len) {
            let errno = args.args[0].clone();
            let msg = args.args[1].clone();
        }
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        idx = [f for f in r["findings"] if f["details"]["pattern"] == "args-index"]
        self.assertTrue(idx)
        for f in idx:
            self.assertTrue(f["details"]["length_guarded"])
            self.assertEqual(f["classification"], "CONSIDER")

    def test_unguarded_arity_index_stays_fix(self) -> None:
        # No length guard (the _typing._idfunc / RUSTPY-0005 shape) → FIX.
        src = """
#[pyfunction]
fn idfunc(args: FuncArgs, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
    Ok(args.args[0].clone())
}
"""
        r = _run({"crates/vm/src/stdlib/typing.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "args-index")
        self.assertFalse(f["details"]["length_guarded"])
        self.assertEqual(f["classification"], "FIX")

    def test_pure_unreachable_stub_is_acceptable(self) -> None:
        # A shadow stub (`unreachable!("slot_init is defined")`) → ACCEPTABLE.
        src = """
impl Initializer for PyFoo {
    fn init(&self) {
        unreachable!("slot_init is defined")
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unreachable")
        self.assertTrue(f["details"]["stub_body"])
        self.assertEqual(f["classification"], "ACCEPTABLE")

    def test_pure_unimplemented_stub_is_acceptable(self) -> None:
        src = """
impl Constructor for PyFoo {
    fn py_new(&self) {
        unimplemented!("use slot_new")
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unimplemented")
        self.assertEqual(f["classification"], "ACCEPTABLE")

    def test_todo_stub_stays_consider(self) -> None:
        # todo! is genuinely unimplemented work — NOT down-ranked.
        src = """
impl PyFoo {
    #[pymethod]
    fn not_done(&self) {
        todo!()
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "todo")
        self.assertFalse(f["details"]["stub_body"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_downcast_of_private_field_read_is_downranked(self) -> None:
        # `self.fut_exception.read()` → the type is an internal invariant; the
        # downcast cannot fail from Python (the _asyncio.rs L229 shape).
        src = """
impl PyFuture {
    #[pymethod]
    fn result(&self, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let fut_exception = self.fut_exception.read().clone();
        if let Some(exc) = fut_exception {
            let exc: PyBaseExceptionRef = exc.downcast().unwrap();
            return Ok(exc.into());
        }
        Ok(vm.ctx.none())
    }
}
"""
        r = _run({"crates/stdlib/src/_asyncio.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertTrue(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_downcast_of_same_var_isinstance_gate_is_downranked(self) -> None:
        # `exc.fast_isinstance(...)` then `exc.downcast()` — same variable gated
        # (the _asyncio.rs L312 shape).
        src = """
impl PyFuture {
    #[pymethod]
    fn set_exception(&self, exc: PyObjectRef, vm: &VirtualMachine) -> PyResult<()> {
        if exc.fast_isinstance(vm.ctx.exceptions.stop_iteration) {
            let stop_iter: PyRef<PyBaseException> = exc.downcast().unwrap();
            return Ok(());
        }
        Ok(())
    }
}
"""
        r = _run({"crates/stdlib/src/_asyncio.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertTrue(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_downcast_of_module_attr_stays_fix(self) -> None:
        # The current_task L2408 bug: downcast a Python-reassignable module
        # attribute — no self-field, no same-var gate → stays FIX.
        src = """
#[pyfunction]
fn current_task(vm: &VirtualMachine) -> PyResult<PyObjectRef> {
    let current_tasks = get_current_tasks_dict(vm)?;
    let dict: PyDictRef = current_tasks.downcast().unwrap();
    Ok(dict.into())
}
"""
        r = _run({"crates/stdlib/src/_asyncio.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertFalse(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "FIX")

    def test_owner_type_downcast_is_downranked(self) -> None:
        # The tuple as_number L488 FP: a protocol slot in `impl AsNumber for
        # PyTuple` downcasting to PyTuple is guarded by the slot-wrapper's
        # fast_isinstance(owner) check → CONSIDER, not FIX.
        src = """
impl AsNumber for PyTuple {
    fn as_number() -> &'static PyNumberMethods {
        fn inner(number: &PyNumber, vm: &VirtualMachine) -> PyResult<bool> {
            let zelf = number.obj.downcast_ref::<PyTuple>().unwrap();
            Ok(!zelf.is_empty())
        }
    }
}
"""
        r = _run({"crates/vm/src/builtins/tuple.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertTrue(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_non_owner_type_downcast_stays_fix(self) -> None:
        # A protocol slot in `impl AsNumber for PyFoo` downcasting to a DIFFERENT
        # type (PyBar, not the owner) is NOT guaranteed by the wrapper → FIX.
        src = """
impl AsNumber for PyFoo {
    fn as_number(&self, other: PyObjectRef) -> PyResult<()> {
        let bar = other.downcast_ref::<PyBar>().unwrap();
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertFalse(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "FIX")

    def test_downcast_with_different_var_gated_stays_fix(self) -> None:
        # The throw L1081 bug: `exc_type` is gated, but `exc` (a distinct value
        # from exc_type.call()) is downcast → must NOT be down-ranked.
        src = """
impl PyFutureIter {
    #[pymethod]
    fn throw(&self, exc_type: PyObjectRef, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let exc = if exc_type.fast_isinstance(vm.ctx.types.type_type) {
            exc_type.call((), vm)?
        } else {
            exc_type
        };
        Err(exc.downcast().unwrap())
    }
}
"""
        r = _run({"crates/stdlib/src/_asyncio.rs": src})
        # the `exc.downcast()` finding — subject `exc`, gate on `exc_type`
        f = next(
            f
            for f in r["findings"]
            if f["details"]["pattern"] == "unwrap" and f["line"] >= 9
        )
        self.assertFalse(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "FIX")

    def test_unreachable_among_other_code_is_not_a_stub(self) -> None:
        # An `unreachable!` after real logic (an exhaustive match) is NOT a pure
        # stub → stays CONSIDER (the agent judges exhaustiveness).
        src = """
impl PyFoo {
    #[pymethod]
    fn m(&self, x: i32) -> i32 {
        let y = x + 1;
        match y {
            0 => 1,
            _ => unreachable!(),
        }
    }
}
"""
        r = _run({"crates/vm/src/builtins/foo.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unreachable")
        self.assertFalse(f["details"]["stub_body"])
        self.assertEqual(f["classification"], "CONSIDER")


class TestWholeTreeCalibrations(unittest.TestCase):
    """Calibration from the first whole-tree run (v0.1.1): owner-downcast on the
    literal `Self`, multi-line downcast chains, aliased-length + same-line
    is_empty guards, and the full-slice exclusion — plus regression guards that
    lock in that none of these down-rank a real bug."""

    def test_self_owner_downcast_is_downranked(self) -> None:
        # `zelf.downcast_ref::<Self>()` in a #[pyslot] — the slot wrapper only
        # dispatches on the owner type, so this is airtight (bytearray/bytes/
        # descriptor/_io shape). Target spelled `Self`, not the concrete type.
        src = """
impl PyByteArray {
    #[pyslot]
    fn slot_str(zelf: &PyObject, vm: &VirtualMachine) -> PyResult<PyStrRef> {
        let zelf = zelf.downcast_ref::<Self>().expect("expected bytearray");
        Ok(zelf.repr(vm)?)
    }
}
"""
        r = _run({"crates/vm/src/builtins/bytearray.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "expect")
        self.assertTrue(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_multiline_self_downcast_is_downranked(self) -> None:
        # The _ctypes/simple.rs:1302 shape: the `.expect()` sits one line below the
        # `.downcast_ref::<Self>()` in a multi-line chain. The 2-line detect window
        # must still see the downcast.
        src = """
impl AsNumber for PyCSimple {
    fn as_number() -> &'static PyNumberMethods {
        fn inner(obj: &PyObject, vm: &VirtualMachine) -> PyResult<bool> {
            let zelf = obj
                .downcast_ref::<Self>()
                .expect("non-PyCSimple");
            Ok(true)
        }
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_ctypes/simple.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "expect")
        self.assertTrue(f["details"]["downcast_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_aliased_length_guard_downranked(self) -> None:
        # `let num_args = args.args.len(); if num_args == 1 { args.args[0] }` — the
        # arity is aliased to a local, which the plain len-adjacent regex misses
        # (type.rs:2806, _thread.rs:495 shape).
        src = """
impl PyType {
    #[pyslot]
    fn slot_call(zelf: PyObjectRef, args: FuncArgs, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let num_args = args.args.len();
        if num_args == 1 {
            return Ok(args.args[0].clone());
        }
        Ok(zelf)
    }
}
"""
        r = _run({"crates/vm/src/builtins/type.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "args-index")
        self.assertTrue(f["details"]["length_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_same_line_isempty_guard_downranked(self) -> None:
        # `if !x.is_empty() && x.last().unwrap()` — a same-line is_empty guard on
        # a .last()/.first() (the _functools.rs:260 shape).
        src = """
impl PyPartial {
    #[pymethod]
    fn check(&self, args_slice: &[PyObjectRef], vm: &VirtualMachine) -> PyResult<()> {
        if !args_slice.is_empty() && is_placeholder(args_slice.last().unwrap()) {
            return Err(vm.new_type_error("no"));
        }
        Ok(())
    }
}
"""
        r = _run({"crates/vm/src/stdlib/_functools.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertTrue(f["details"]["length_guarded"])
        self.assertEqual(f["classification"], "CONSIDER")

    def test_full_slice_match_not_flagged_as_index(self) -> None:
        # `match &args.args[..]` is a full-slice reborrow (never panics); its arms
        # handle arity (set.rs:989). No args-index finding should be emitted.
        src = """
impl PySet {
    #[pyslot]
    fn slot_new(args: FuncArgs, vm: &VirtualMachine) -> PyResult<Self> {
        match &args.args[..] {
            [] => Ok(Self::default()),
            _ => Ok(Self::default()),
        }
    }
}
"""
        r = _run({"crates/vm/src/builtins/set.rs": src})
        self.assertFalse(
            [f for f in r["findings"] if f["details"]["pattern"] == "args-index"]
        )

    # --- regression guards: these must STAY FIX (the two bugs found in review) ---

    def test_different_line_isempty_does_not_downrank(self) -> None:
        # REGRESSION (mmap.rs:795): a `sub.is_empty()` guarding an unrelated
        # empty-substring branch several lines above must NOT down-rank a later
        # fallible access. is_empty is trusted only on the SAME line.
        src = """
impl PyMmap {
    #[pymethod]
    fn find(&self, options: FindOptions, vm: &VirtualMachine) -> PyResult<PyInt> {
        let sub = &options.sub;
        if sub.is_empty() {
            return Ok(PyInt::from(0));
        }
        let n = options.value.downcast::<PyInt>().unwrap();
        Ok(PyInt::from(0))
    }
}
"""
        r = _run({"crates/vm/src/stdlib/mmap.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertFalse(f["details"]["length_guarded"])
        self.assertEqual(f["classification"], "FIX")

    def test_comment_does_not_fake_arity_guard(self) -> None:
        # REGRESSION (itertools.rs:1412): a `let n = pool.len()` plus a comment
        # `// r == n` must NOT satisfy the arity-alias guard — comments are
        # stripped from the guard window before matching.
        src = """
impl PyItertoolsPermutations {
    #[pyslot]
    fn slot_new(iterable: PyObjectRef, r: PyIntRef, vm: &VirtualMachine) -> PyResult<Self> {
        let pool: Vec<PyObjectRef> = iterable.try_to_value(vm)?;
        let n = pool.len();
        // If r is not provided, r == n.
        let r = r.as_bigint();
        let r = r.to_usize().unwrap();
        Ok(Self::default())
    }
}
"""
        r = _run({"crates/vm/src/stdlib/itertools.rs": src})
        f = next(f for f in r["findings"] if f["details"]["pattern"] == "unwrap")
        self.assertFalse(f["details"]["length_guarded"])
        self.assertEqual(f["classification"], "FIX")


if __name__ == "__main__":
    unittest.main()
