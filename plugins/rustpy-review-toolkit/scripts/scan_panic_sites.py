#!/usr/bin/env python3
"""Flagship scanner: Python-reachable panic sites in the RustPython VM.

RustPython's dominant crash class is a native ``.unwrap()`` / ``.expect()`` /
``panic!`` / unchecked index reached from a Python program (12 of the 24
confirmed fuzzer findings). Unlike a soundness bug, a panic here doesn't corrupt
memory — it aborts the interpreter (or unwinds), turning any Python call into a
denial-of-service. This scanner finds every such site and **ranks it by
reachability tier**, so the ones a Python program can actually trigger surface
while the interpreter's internal invariants stay quiet.

The classification (which fn is `py` / `protocol` / `internal`) comes from
``map_rustpy_internals.classify_functions`` — the single source of truth. This
scanner overlays two things on top:

1. **Tier gating.** Panics in `internal`-tier helpers are DEFAULT-SILENCED
   (counted, not emitted) — they are not directly Python-triggerable, and
   emitting them drowns the signal. Pass ``--include-internal`` to surface them.
2. **Reachability ranking.** For each `py`/`protocol` site, the failing value's
   provenance is scored against ``rustpython_reachability_sources.json`` — a
   panic on a value that flows from a Python argument / a downcast / an int
   narrowing / a user index is a real remotely-triggerable crash (FIX); one on a
   VM-established invariant is weaker (CONSIDER).

Port of the fuzzing seed tool ``unwrap_scan`` (rustpython-findings) to
Python + tree-sitter, plus the reachability ranking the seed did not have.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from map_rustpy_internals import classify_functions, load_protocol_traits  # noqa: E402
from rust_ts_utils import parse_bytes, strip_comments  # noqa: E402
from scan_common import (  # noqa: E402
    deduplicate_findings,
    discover_rust_files,
    load_data_file,
    make_finding,
    parse_common_args,
    relative_path,
)

# Risky patterns (substring match on non-comment lines). Ported from the
# fuzzing seed tool's PATTERNS. ``args-index`` catches arity OOB (the
# `_typing._idfunc` face: indexing `args[N]` without checking arity).
PATTERNS: tuple[tuple[str, str], ...] = (
    (".unwrap()", "unwrap"),
    (".expect(", "expect"),
    ("panic!", "panic"),
    ("unreachable!", "unreachable"),
    ("unimplemented!", "unimplemented"),
    ("todo!", "todo"),
    (".args[", "args-index"),
)

# Patterns that panic on a *fallible value* (as opposed to an explicit abort
# macro). These are the ones the reachability ranking is meaningful for.
_FALLIBLE_VALUE_PATTERNS = frozenset({"unwrap", "expect", "args-index"})

# A length/arity guard in the enclosing context — an `if (2..=5).contains(&len)`,
# a `match args.len()` arm, an `if len == 2`, etc. When a fallible-value panic
# (typically `args[N]` / `get_arg(N)`) sits inside one, the index is bounded and
# the site is very likely a false positive; it is down-ranked to CONSIDER. An
# UNGUARDED arity index (the `_typing._idfunc` shape, RUSTPY-0005) has no such
# guard and stays FIX. Calibration from the exceptions.rs deep-dive, where all
# 14 scanner-FIX arity indices were guarded false positives.
_LENGTH_GUARD_RE = re.compile(
    r"\.len\(\)\s*(?:==|!=|>=|<=|>|<)"  # x.len() == N
    r"|(?:==|!=|>=|<=|>|<)\s*[\w.]*\.?len\(\)"  # N <= x.len()
    r"|(?:==|>=|<=|>|<)\s*len\b"  # >= len
    r"|\blen\s*(?:==|>=|<=|>|<)"  # len >= N
    r"|match\s+[\w.]+\.len\(\)"  # match x.len()
    r"|\.contains\(&?\s*\w*len"  # (N..=M).contains(&len)
)
# How far back to look for the guard (covers a match arm / if-block header,
# including guards a nested block pushes ~14 lines above the index).
_GUARD_LOOKBACK = 16

# An arity bound to a local (`let given = f_args.args.len();`) and then compared
# (`if given < 2`, `if num_args == 1`) is a length guard the plain regex above
# cannot see — the intermediate binding breaks the `len()`-adjacent-to-comparison
# shape it keys on. Detect the alias binding + a comparison on that same local.
# Calibration from the whole-tree run (`type.rs:2806`, `_thread.rs:495/496`).
_LEN_ALIAS_RE = re.compile(r"\blet\s+(\w+)\s*=\s*[^;]*\.len\(\)")

# A full-slice reborrow `x[..]` never panics (unlike an index `x[N]`), so an
# `args-index` hit that is really `.args[..]` (typically `match &args.args[..]`,
# whose arms handle arity) is not a crash site. Calibration from `set.rs:989`.
_FULL_SLICE_RE = re.compile(r"\.args\s*\[\s*\.\.\s*\]")

# A `.is_empty()` guard is only trusted on the SAME line as the fallible access
# (`if !x.is_empty() && x.last().unwrap()`, `_functools.rs:260`). A bare
# `.is_empty()` elsewhere in the window guards an unrelated case (e.g. mmap's
# `sub.is_empty()` protects the empty-substring branch, NOT the `[start..end]`
# slice) and must not down-rank — hence same-line only.
_SAME_LINE_EMPTY_RE = re.compile(r"\.is_empty\(\)")

# `//` line comments in the guard window can fake a guard (`// r == n` looks like
# an arity comparison); strip them before matching. Calibration from the
# whole-tree run (`itertools.rs:1412` permutations, whose `let n = pool.len()` +
# the comment `// r == n` falsely satisfied the arity-alias guard).
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_line_comments(text: str) -> str:
    """Drop `//` line comments so a comment cannot fake a guard."""
    return _LINE_COMMENT_RE.sub("", text)


def _arity_alias_guarded(window_text: str) -> bool:
    """True if an arity is bound to a local (`let n = x.len()`) and compared."""
    for m in _LEN_ALIAS_RE.finditer(window_text):
        var = re.escape(m.group(1))
        if re.search(rf"\b{var}\s*(?:==|!=|>=|<=|>|<)", window_text) or re.search(
            rf"(?:==|!=|>=|<=|>|<)\s*{var}\b", window_text
        ):
            return True
    return False


# A function body that is nothing but a single `unreachable!(...)` /
# `unimplemented!(...)` macro is a deliberate "this is not the live impl" marker
# — in RustPython these shadow a sibling `slot_*` form (`unreachable!("slot_init
# is defined")`, `unimplemented!("use slot_new")`). The panic in such a stub is
# not a data-dependent crash, so it is classified ACCEPTABLE rather than
# surfaced. `todo!` is deliberately NOT included — a `todo!()` body is genuinely
# unimplemented work worth a CONSIDER. Calibration from the exceptions.rs
# meta-eval (10+ shadowed `unreachable!` init stubs).
_STUB_BODY_RE = re.compile(
    r"^(?:unreachable|unimplemented)!\s*\(.*?\)\s*;?$", re.DOTALL
)


def _is_pure_abort_stub(body_node: object, source: bytes) -> bool:
    """True if a fn body is nothing but one `unreachable!`/`unimplemented!`."""
    inner = (
        strip_comments(
            source[body_node.start_byte : body_node.end_byte]  # type: ignore[attr-defined]
        )
        .decode("utf-8", "replace")
        .strip()
    )
    if inner.startswith("{"):
        inner = inner[1:]
    if inner.endswith("}"):
        inner = inner[:-1]
    return bool(_STUB_BODY_RE.match(inner.strip()))


# `X.downcast().unwrap()` — an invariant-protected downcast, distinct from a
# Python-controllable one. Calibration from the _asyncio.rs meta-eval, where
# 7 of 9 scanner-FIX were downcasts that cannot fail: either the subject is read
# from a private `PyRwLock` payload field (`self.fut_exception.read()` → the type
# is an internal invariant) or the SAME variable was `fast_isinstance`-gated just
# above. The genuinely-exploitable downcasts (a Python-reassignable module
# attribute, `current_task` L2408; a `__new__`-controlled `.call()` result,
# `throw` L1081) have neither, so they stay FIX. The gate must be on the SAME
# variable as the downcast subject: `throw` gates `exc_type` but downcasts `exc`
# (a different value), which is exactly why it remains a (real) FIX.
_DOWNCAST_SUBJECT_RE = re.compile(r"(\w+)\s*(?:\.clone\(\)\s*)?\.downcast\b")
_PRIVATE_FIELD_READ_RE = re.compile(
    r"self\.\w+(?:\.\w+)*\.(?:read|write|lock|try_read|try_write)\s*\("
)
# The turbofish target of a downcast: `.downcast_ref::<PyTuple>()` → `PyTuple`.
_DOWNCAST_TARGET_RE = re.compile(
    r"\.downcast(?:_ref|_exact)?\s*::\s*<\s*([A-Za-z_][\w:]*)"
)
_DOWNCAST_LOOKBACK = 10
# The downcast that a `.unwrap()`/`.expect()` fails on can sit one line up in a
# multi-line method chain (`let zelf = obj\n.downcast_ref::<Self>()\n.expect(…)`).
# Detect the downcast over the current line + this many preceding lines so those
# splits are seen. Calibration from the whole-tree run (`_ctypes/simple.rs:1302`).
_DOWNCAST_DETECT_LOOKBACK = 2


def _bare_type(text: str) -> str:
    """Last path segment of a type: `crate::PyTuple` → `PyTuple`."""
    return text.rsplit("::", 1)[-1].strip()


def _downcast_downranked(
    detect_text: str, window_text: str, self_type: str | None = None
) -> bool:
    """True if a `.downcast().unwrap()` is invariant-protected.

    Down-ranks when: the subject is a private RwLock field read; the SAME
    variable was `fast_isinstance`/`fast_issubclass`-gated in the window; or the
    downcast target type is the ENCLOSING impl's own type — a protocol/py slot in
    `impl … for X` downcasting to `X` (or, equivalently, to the literal `Self`).
    The slot-wrapper's `fast_isinstance(X)` guard makes the owner-downcast
    airtight, since X's subclasses share X's Rust payload; this is the
    `as_number` L488 (tuple.rs) and the `zelf.downcast::<Self>()` slot class
    (bytearray/bytes/descriptor/_io, whole-tree run). ``detect_text`` is the
    current line plus a couple preceding lines, so a multi-line downcast chain is
    still recognized. Never down-ranks a distinct Python-controllable value (a
    module attribute, a `.call()` result, or a downcast whose target differs from
    the slot owner) — those keep their FIX.
    """
    if ".downcast" not in detect_text:
        return False
    # Owner-type downcast: target is the enclosing impl's Self type, or the
    # literal `Self` (the same type inside `impl … for X`).
    if self_type:
        tm = _DOWNCAST_TARGET_RE.search(detect_text)
        if tm is not None:
            target = _bare_type(tm.group(1))
            if target == _bare_type(self_type) or target == "Self":
                return True
    m = _DOWNCAST_SUBJECT_RE.search(detect_text)
    if m is None:
        return False
    subject = m.group(1)
    if subject == "self":
        return True
    if re.search(
        rf"\b{re.escape(subject)}\.fast_is(?:instance|subclass)\s*\(", window_text
    ):
        return True
    return bool(_PRIVATE_FIELD_READ_RE.search(window_text))


def _load_reachability() -> tuple[list[dict], list[str]]:
    """Return (categories, weak_internal_tokens) from the data file."""
    data = load_data_file("rustpython_reachability_sources.json")
    cats = data.get("categories", []) if isinstance(data, dict) else []
    weak_block = data.get("weak_internal_signals", {}) if isinstance(data, dict) else {}
    weak = weak_block.get("tokens", []) if isinstance(weak_block, dict) else []
    return (cats if isinstance(cats, list) else []), (
        weak if isinstance(weak, list) else []
    )


def _reachability_signals(
    window_text: str, cats: list[dict], weak: list[str]
) -> tuple[list[str], bool, bool]:
    """Score a candidate's context window against the reachability sources.

    Returns (matched_category_names, has_high_weight_signal, has_weak_signal).
    """
    matched: list[str] = []
    high = False
    for c in cats:
        tokens = c.get("tokens", []) if isinstance(c, dict) else []
        if any(str(t) in window_text for t in tokens):
            matched.append(str(c.get("name", "")))
            if c.get("weight") == "high":
                high = True
    has_weak = any(str(t) in window_text for t in weak)
    return matched, high, has_weak


def _classify(tier: str, pattern: str, high: bool, has_weak: bool) -> tuple[str, str]:
    """Map (tier, pattern, signals) → (classification, confidence).

    Calibration (design §6):
      * internal tier → ACCEPTABLE (silenced unless --include-internal)
      * py/protocol + fallible-value pattern + high Python-controlled signal
        and no weak-invariant signal → FIX (a Python program can abort the VM)
      * py/protocol + fallible-value pattern otherwise → CONSIDER
      * py/protocol + explicit abort macro (panic!/unreachable!/todo!) →
        CONSIDER (often a deliberate "can't happen"; the agent verifies whether
        a Python path reaches it)
    """
    if tier == "internal":
        return "ACCEPTABLE", "LOW"
    if pattern in _FALLIBLE_VALUE_PATTERNS:
        if high and not has_weak:
            return "FIX", "HIGH"
        if has_weak:
            return "CONSIDER", "LOW"
        return "CONSIDER", "MEDIUM"
    # Explicit abort macros: reachable, but usually intentional.
    return ("CONSIDER", "MEDIUM") if high else ("CONSIDER", "LOW")


def analyze(target: str, *, max_files: int = 0, include_internal: bool = False) -> dict:
    """Scan RustPython at ``target`` for Python-reachable panic sites."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    protocol_traits = load_protocol_traits()
    cats, weak = _load_reachability()

    findings: list[dict] = []
    internal_suppressed = 0
    total_fns = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        default_module = path.parent.name
        rel = relative_path(path, project_root)
        lines = source.decode("utf-8", "replace").splitlines()

        for fn in classify_functions(
            tree, source, default_module, protocol_traits=protocol_traits
        ):
            total_fns += 1
            body = fn["body_node"]
            if body is None:
                continue
            tier = fn["reachable"]
            is_stub = _is_pure_abort_stub(body, source)
            b_start = body.start_point[0] + 1
            b_end = body.end_point[0] + 1
            for ln in range(b_start, min(b_end, len(lines)) + 1):
                raw = lines[ln - 1]
                if raw.lstrip().startswith("//"):
                    continue
                for needle, pattern in PATTERNS:
                    if needle not in raw:
                        continue
                    # A full-slice reborrow `.args[..]` never panics — not a
                    # crash site, even though it matches the `.args[` needle.
                    if pattern == "args-index" and _FULL_SLICE_RE.search(raw):
                        continue
                    if tier == "internal" and not include_internal:
                        internal_suppressed += 1
                        continue
                    window = "\n".join(lines[max(0, ln - 4) : ln])
                    matched, high, has_weak = _reachability_signals(window, cats, weak)
                    # A fallible-value panic inside a length/arity guard is very
                    # likely a bounded false positive → down-rank like a weak
                    # signal. Covers a direct `.len()`/`.is_empty()` guard and an
                    # arity aliased to a local (`let n = x.len(); if n == 1`). An
                    # unguarded arity index stays FIX.
                    guard_window = _strip_line_comments(
                        "\n".join(lines[max(0, ln - _GUARD_LOOKBACK) : ln])
                    )
                    guarded = pattern in _FALLIBLE_VALUE_PATTERNS and (
                        bool(_LENGTH_GUARD_RE.search(guard_window))
                        or _arity_alias_guarded(guard_window)
                        or bool(_SAME_LINE_EMPTY_RE.search(raw))
                    )
                    # An invariant-protected downcast (owner-type / private-field
                    # read / same-variable isinstance gate) is not
                    # Python-controllable. Detected over a small multi-line window
                    # so a split `obj\n.downcast_ref::<Self>()\n.expect()` is seen.
                    downcast_guarded = (
                        pattern in _FALLIBLE_VALUE_PATTERNS
                        and _downcast_downranked(
                            "\n".join(
                                lines[max(0, ln - _DOWNCAST_DETECT_LOOKBACK) : ln]
                            ),
                            "\n".join(lines[max(0, ln - _DOWNCAST_LOOKBACK) : ln]),
                            fn["class"],
                        )
                    )
                    classification, confidence = _classify(
                        tier, pattern, high, has_weak or guarded or downcast_guarded
                    )
                    # A pure abort-macro stub body is a deliberate shadow marker,
                    # not a data crash → ACCEPTABLE.
                    if is_stub and pattern in ("unreachable", "unimplemented"):
                        classification, confidence = "ACCEPTABLE", "LOW"
                    snippet = raw.strip()[:100]
                    findings.append(
                        make_finding(
                            "panic_site",
                            classification=classification,
                            confidence=confidence,
                            description=(
                                f"{pattern} in {tier}-reachable {fn['kind']} "
                                f"{fn['qualified_name']} (module {fn['module']}): {snippet}"
                            ),
                            file=rel,
                            line=ln,
                            function=fn["qualified_name"],
                            category=tier,
                            details={
                                "pattern": pattern,
                                "tier": tier,
                                "kind": fn["kind"],
                                "python_name": fn["python_name"],
                                "class": fn["class"],
                                "module": fn["module"],
                                "trait": fn["trait"],
                                "reachability_signals": matched,
                                "high_reachability": high,
                                "weak_invariant_signal": has_weak,
                                "length_guarded": guarded,
                                "downcast_guarded": downcast_guarded,
                                "stub_body": is_stub,
                            },
                        )
                    )

    findings = deduplicate_findings(findings)
    report = build_rustpy_report(discovery, findings, functions_analyzed=total_fns)
    report["panic_scan"] = {
        "internal_sites_suppressed": internal_suppressed,
        "include_internal": include_internal,
        "patterns": [p for _, p in PATTERNS],
    }
    return report


def main() -> None:
    try:
        argv = sys.argv[1:]
        include_internal = "--include-internal" in argv
        argv = [a for a in argv if a != "--include-internal"]
        target, max_files = parse_common_args(argv)
        result = analyze(target, max_files=max_files, include_internal=include_internal)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except Exception as e:  # noqa: BLE001 -- top-level guard, emit JSON error
        json.dump({"error": str(e), "type": type(e).__name__}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
