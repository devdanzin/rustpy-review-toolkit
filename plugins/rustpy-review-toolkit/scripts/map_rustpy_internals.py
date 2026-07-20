#!/usr/bin/env python3
"""Map RustPython's macro object model — the preflight orientation index.

This is the genuinely novel primitive of the toolkit. It walks RustPython's
derive-macro surface and attributes every Rust site to (a) its Python-facing
name and (b) its **reachability tier** — ``py`` > ``protocol`` > ``internal`` —
so the panic-site auditor can rank a ``.unwrap()`` by how directly a Python
program can reach it, and the gc-traverse auditor can find ``#[pyclass]``
payloads that own Python references.

Attribution rules (ported from the fuzzing seed tool's ``classify_method`` and
verified against ``crates/derive-impl/src/``):

  * ``#[pymodule]``            → a native module; Python name = ``name="…"`` or ident
  * ``#[pyfunction]`` free fn  → ``py`` tier
  * impl method with one of
    ``#[pymethod|pygetset|pyslot|pystaticmethod|pyclassmethod]`` → ``py`` tier
    (``#[pymethod(magic)]`` → ``__ident__``)
  * a method inside an ``impl <ProtocolTrait> for <X>`` (Representable, AsMapping,
    …) → ``protocol`` tier — the ``#[pyclass(with(Trait))]`` slot surface, which
    is Python-reachable without any per-method attribute
  * anything else → ``internal`` tier (reached only transitively)

The two extraction helpers (``classify_functions``, ``extract_pyclass_payloads``)
are the single source of truth imported by ``scan_panic_sites`` and
``scan_gc_traverse`` — the classification is defined here exactly once.

Analysis is purely syntactic (tree-sitter): the ``with(Trait)`` protocol slots
are attributed to the trait impl's own methods, not re-mapped to the owning
class's dunder names (that cross-file resolution is future work) — but they are
still correctly tiered ``protocol``.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_rustpy import build_rustpy_report, discover  # noqa: E402
from rust_ts_utils import (  # noqa: E402
    extract_attributes,
    extract_struct_defs,
    node_line,
    parse_bytes,
    text_of,
    walk,
)
from scan_common import (  # noqa: E402
    discover_rust_files,
    load_data_file,
    parse_common_args,
    relative_path,
)


def _root_node(tree_or_node: Any) -> Any:
    """The root Node of a Tree, or the node itself if already a Node."""
    return (
        tree_or_node.root_node if hasattr(tree_or_node, "root_node") else tree_or_node
    )


# Fallback if the data file is missing; kept in sync with
# data/rustpython_protocol_traits.json.
_DEFAULT_PROTOCOL_TRAITS = frozenset(
    {
        "Representable",
        "Hashable",
        "Comparable",
        "Iterable",
        "IterNext",
        "IterNextIterable",
        "AsMapping",
        "AsSequence",
        "AsNumber",
        "AsBuffer",
        "Callable",
        "Constructor",
        "Initializer",
        "GetDescriptor",
        "GetAttr",
        "SetAttr",
        "GetSet",
        "Destructor",
        "PyStructSequence",
        "DefaultConstructor",
        "Unconstructible",
    }
)

# Exposing attributes → (kind, tier). Order matters only for kind labelling.
_EXPOSING_METHOD_ATTRS = {
    "pymethod": "method",
    "pygetset": "getset",
    "pyslot": "slot",
    "pystaticmethod": "staticmethod",
    "pyclassmethod": "classmethod",
}

_NAME_OVERRIDE_RE = re.compile(r'\bname\s*=\s*"([^"]*)"')


def load_protocol_traits() -> frozenset[str]:
    """The protocol-trait set, from the data file (fallback to the default)."""
    data = load_data_file("rustpython_protocol_traits.json")
    traits = data.get("protocol_traits") if isinstance(data, dict) else None
    if isinstance(traits, list) and traits:
        return frozenset(str(t) for t in traits)
    return _DEFAULT_PROTOCOL_TRAITS


def _bare_ident(type_text: str | None) -> str:
    """Strip generics and path scoping: ``crate::Foo<T>`` → ``Foo``."""
    if not type_text:
        return ""
    text = type_text.split("<", 1)[0].strip()
    text = text.rsplit("::", 1)[-1]
    return text.strip().lstrip("&").strip()


def _name_override(args_text: str | None) -> str | None:
    """Extract ``name = "…"`` from an attribute's args, if present."""
    if not args_text:
        return None
    m = _NAME_OVERRIDE_RE.search(args_text)
    return m.group(1) if m else None


def _has_flag(args_text: str | None, flag: str) -> bool:
    """True if a bare ``flag`` token appears in the attribute args."""
    if not args_text:
        return False
    return (
        re.search(rf"(?:^|[(,\s]){re.escape(flag)}\s*(?:,|$|[)\s])", args_text)
        is not None
    )


def _find_attr(attrs: list[dict], name: str) -> dict | None:
    """The first attribute in ``attrs`` whose leaf name is ``name``."""
    for a in attrs:
        if a.get("name") == name:
            return a
    return None


def _python_name(attr: dict, ident: str, *, magic_ok: bool) -> str:
    """Derive the Python name from an exposing attribute (override / magic / ident)."""
    override = _name_override(attr.get("args_text"))
    if override:
        return override
    if magic_ok and _has_flag(attr.get("args_text"), "magic"):
        return f"__{ident}__"
    return ident


def _item_body(node: Any) -> Any:
    """The declaration_list body of a mod_item / impl_item, or None."""
    body = node.child_by_field_name("body")
    if body is not None:
        return body
    for c in node.children:
        if c.type == "declaration_list":
            return c
    return None


def _classified(
    rust_name: str,
    python_name: str,
    klass: str | None,
    module: str,
    kind: str,
    reachable: str,
    trait: str | None,
    node: Any,
) -> dict:
    qualified = f"{klass}.{python_name}" if klass else python_name
    return {
        "rust_name": rust_name,
        "python_name": python_name,
        "qualified_name": qualified,
        "class": klass,
        "module": module,
        "kind": kind,
        "reachable": reachable,
        "trait": trait,
        "start_line": node_line(node),
        "end_line": node.end_point[0] + 1,
        "body_node": node.child_by_field_name("body"),
    }


def _walk_classify(
    container: Any,
    source: bytes,
    module: str,
    protocol_traits: frozenset[str],
    out: list[dict],
) -> None:
    """Recursively classify fn/method items under ``container`` (a source_file
    or declaration_list), tracking the enclosing ``#[pymodule]`` module."""
    for child in container.children:
        ctype = child.type
        if ctype == "mod_item":
            attrs = extract_attributes(child, source)
            pymod = _find_attr(attrs, "pymodule")
            name_node = child.child_by_field_name("name")
            ident = text_of(name_node, source) if name_node is not None else ""
            new_module = module
            if pymod is not None:
                new_module = _name_override(pymod.get("args_text")) or ident
            body = _item_body(child)
            if body is not None:
                _walk_classify(body, source, new_module, protocol_traits, out)
        elif ctype == "function_item":
            name_node = child.child_by_field_name("name")
            if name_node is None:
                continue
            ident = text_of(name_node, source)
            attrs = extract_attributes(child, source)
            pyfn = _find_attr(attrs, "pyfunction")
            if pyfn is not None:
                out.append(
                    _classified(
                        ident,
                        _python_name(pyfn, ident, magic_ok=False),
                        None,
                        module,
                        "function",
                        "py",
                        None,
                        child,
                    )
                )
            else:
                out.append(
                    _classified(
                        ident, ident, None, module, "helper", "internal", None, child
                    )
                )
        elif ctype == "impl_item":
            type_node = child.child_by_field_name("type")
            klass = (
                _bare_ident(text_of(type_node, source)) if type_node is not None else ""
            )
            trait_node = child.child_by_field_name("trait")
            trait = (
                _bare_ident(text_of(trait_node, source))
                if trait_node is not None
                else None
            )
            is_protocol = trait in protocol_traits if trait else False
            body = _item_body(child)
            if body is None:
                continue
            for m in body.children:
                if m.type != "function_item":
                    continue
                mname_node = m.child_by_field_name("name")
                if mname_node is None:
                    continue
                mident = text_of(mname_node, source)
                mattrs = extract_attributes(m, source)
                out.append(
                    _classify_method(
                        mident,
                        mattrs,
                        klass or None,
                        module,
                        trait,
                        is_protocol,
                        m,
                    )
                )
        elif ctype == "trait_item":
            # A trait DEFINITION with default method bodies. The Python-reachable
            # protocol slots are the `impl <Trait> for <Type>` overrides (handled
            # above); a trait's own default-method bodies are internal machinery
            # (e.g. StaticType::static_type). Classify them `internal` — surfaced
            # only with --include-internal — so panics inside trait defaults are
            # still catchable without adding protocol-tier noise. Conservative:
            # an unoverridden protocol-trait default is under-tiered (a false
            # negative, not a false positive), which v0.1 accepts.
            body = _item_body(child)
            if body is None:
                continue
            for m in body.children:
                if m.type != "function_item":
                    continue
                mname_node = m.child_by_field_name("name")
                if mname_node is None or m.child_by_field_name("body") is None:
                    continue  # a signature-only trait method has no body to scan
                mident = text_of(mname_node, source)
                out.append(
                    _classified(
                        mident,
                        mident,
                        None,
                        module,
                        "trait-default",
                        "internal",
                        None,
                        m,
                    )
                )


def _classify_method(
    ident: str,
    attrs: list[dict],
    klass: str | None,
    module: str,
    trait: str | None,
    is_protocol: bool,
    node: Any,
) -> dict:
    """Classify one impl method into a ClassifiedFn dict."""
    for attr_name, kind in _EXPOSING_METHOD_ATTRS.items():
        attr = _find_attr(attrs, attr_name)
        if attr is None:
            continue
        if attr_name == "pygetset" and _has_flag(attr.get("args_text"), "setter"):
            kind = "getset-setter"
        magic_ok = attr_name == "pymethod"
        name = (
            ident
            if attr_name == "pyslot"
            else _python_name(attr, ident, magic_ok=magic_ok)
        )
        return _classified(ident, name, klass, module, kind, "py", trait, node)
    if is_protocol:
        return _classified(
            ident, ident, klass, module, "protocol", "protocol", trait, node
        )
    return _classified(ident, ident, klass, module, "helper", "internal", trait, node)


def classify_functions(
    tree_or_node: object,
    source: bytes,
    default_module: str,
    *,
    protocol_traits: frozenset[str] | None = None,
) -> list[dict]:
    """Classify every fn/method in a parsed file into ClassifiedFn dicts.

    Each dict carries ``rust_name``, ``python_name``, ``qualified_name``,
    ``class``, ``module``, ``kind``, ``reachable`` (py/protocol/internal),
    ``trait``, ``start_line``, ``end_line`` and ``body_node`` (a tree-sitter
    Node, stripped before JSON serialisation). This is the single source of
    truth consumed by ``scan_panic_sites``.
    """
    if protocol_traits is None:
        protocol_traits = load_protocol_traits()
    out: list[dict] = []
    _walk_classify(
        _root_node(tree_or_node), source, default_module, protocol_traits, out
    )
    return out


# --------------------------------------------------------------------------
# #[pyclass] payloads (for the gc-traverse auditor)
# --------------------------------------------------------------------------


def _traverse_option(args_text: str | None) -> str | None:
    """The ``traverse`` option of a struct-level ``#[pyclass(...)]``.

    Returns ``"manual"`` for ``traverse = "manual"``, ``"auto"`` for a bare
    ``traverse`` flag (auto ``#[derive(Traverse)]``), or ``None`` when absent
    (no GC tracking — ``HAS_TRAVERSE=false``).
    """
    if not args_text:
        return None
    if re.search(r'\btraverse\s*=\s*"manual"', args_text):
        return "manual"
    if _has_flag(args_text, "traverse"):
        return "auto"
    return None


def _struct_field_attrs(field_node: Any, source: bytes) -> list[dict]:
    """Attributes decorating a struct field (its preceding attribute_item siblings)."""
    return extract_attributes(field_node, source)


def extract_pyclass_payloads(
    tree_or_node: object, source: bytes, default_module: str
) -> list[dict]:
    """Extract ``#[pyclass]`` / ``#[pyexception]`` payloads with traverse + fields.

    Returns dicts with ``rust_name``, ``python_name``, ``module``, ``macro``
    (``"pyclass"`` or ``"pyexception"``), ``traverse_option``
    (None/"auto"/"manual"), ``has_derive_traverse`` (a separate
    ``#[derive(Traverse)]``), ``fields`` (each with ``name``, ``type``, ``skip``
    for ``#[pytraverse(skip)]``), ``line``. Consumed by ``scan_gc_traverse``.

    ``#[pyexception]`` is RustPython's domain-specific exception-payload macro
    (it expands to ``#[pyclass]`` at macro-expansion time, which a syntactic
    tree-sitter pass cannot see). Recognising it directly closes the
    exception-machinery blind spot: the transparent-newtype subtypes
    (``struct PyKeyError(PyLookupError);``) are tuple structs with an empty
    named-field list, so they correctly produce no gc finding (their payload is
    the reused base's); a future custom exception payload that adds a ref field
    and forgets its manual ``Traverse`` is now caught. Enums are reported with an
    empty field list (their variants need a deeper walk when needed).
    """
    root = _root_node(tree_or_node)
    out: list[dict] = []
    struct_defs = {sd["node"].id: sd for sd in extract_struct_defs(root, source)}

    for node in list(walk(root, "struct_item")) + list(walk(root, "enum_item")):
        attrs = extract_attributes(node, source)
        payload_attr = _find_attr(attrs, "pyclass") or _find_attr(attrs, "pyexception")
        if payload_attr is None:
            continue
        macro = payload_attr["name"]
        name_node = node.child_by_field_name("name")
        rust_name = text_of(name_node, source) if name_node is not None else ""
        args = payload_attr.get("args_text")
        python_name = _name_override(args) or rust_name
        module = _name_override_module(args) or default_module
        has_derive_traverse = any(
            a.get("name") == "derive" and "Traverse" in (a.get("args_text") or "")
            for a in attrs
        )
        fields: list[dict] = []
        sd = struct_defs.get(node.id)
        if sd is not None:
            for f in sd["fields"]:
                fnode = f.get("node")
                skip = False
                if fnode is not None:
                    fattrs = _struct_field_attrs(fnode, source)
                    pt = _find_attr(fattrs, "pytraverse")
                    skip = pt is not None and _has_flag(pt.get("args_text"), "skip")
                fields.append(
                    {"name": f.get("name", ""), "type": f.get("type", ""), "skip": skip}
                )
        out.append(
            {
                "rust_name": rust_name,
                "python_name": python_name,
                "module": module,
                "macro": macro,
                "traverse_option": _traverse_option(args),
                "has_derive_traverse": has_derive_traverse,
                "fields": fields,
                "is_enum": node.type == "enum_item",
                "line": node_line(node),
            }
        )
    return out


_MODULE_OVERRIDE_RE = re.compile(r'\bmodule\s*=\s*"([^"]*)"')


def _name_override_module(args_text: str | None) -> str | None:
    """Extract ``module = "…"`` from a ``#[pyclass(...)]`` arg list."""
    if not args_text:
        return None
    m = _MODULE_OVERRIDE_RE.search(args_text)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# The mapper report (what the rustpy-internals-mapper agent runs)
# --------------------------------------------------------------------------


def _strip_nodes(fn: dict) -> dict:
    """A JSON-safe copy of a ClassifiedFn (drops the tree-sitter body_node)."""
    return {k: v for k, v in fn.items() if k != "body_node"}


def analyze(target: str, *, max_files: int = 0) -> dict:
    """Build the orientation index for RustPython at ``target``."""
    discovery = discover(target)
    scan_root = Path(discovery["scan_root"])
    project_root = Path(discovery["project_root"])
    files = discover_rust_files(scan_root, max_files=max_files)
    protocol_traits = load_protocol_traits()

    tier_counts = {"py": 0, "protocol": 0, "internal": 0}
    kind_counts: dict[str, int] = {}
    module_names: set[str] = set()
    classes: list[dict] = []
    protocol_impls: dict[str, int] = {}  # trait -> impl count
    exposed_functions: list[dict] = []
    total_fns = 0

    for path in files:
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parse_bytes(source)
        default_module = path.parent.name
        rel = relative_path(path, project_root)

        fns = classify_functions(
            tree, source, default_module, protocol_traits=protocol_traits
        )
        for fn in fns:
            total_fns += 1
            tier_counts[fn["reachable"]] = tier_counts.get(fn["reachable"], 0) + 1
            kind_counts[fn["kind"]] = kind_counts.get(fn["kind"], 0) + 1
            module_names.add(fn["module"])
            if fn["trait"] and fn["reachable"] == "protocol":
                protocol_impls[fn["trait"]] = protocol_impls.get(fn["trait"], 0) + 1
            if fn["reachable"] in ("py", "protocol"):
                rec = _strip_nodes(fn)
                rec["file"] = rel
                exposed_functions.append(rec)

        for payload in extract_pyclass_payloads(tree, source, default_module):
            rec = dict(payload)
            rec["file"] = rel
            classes.append(rec)

    findings: list[dict] = []  # the mapper reports orientation, not findings
    report = build_rustpy_report(discovery, findings, functions_analyzed=total_fns)
    report["orientation"] = {
        "reachability_tiers": tier_counts,
        "kind_counts": kind_counts,
        "module_count": len(module_names),
        "modules": sorted(module_names),
        "class_count": len(classes),
        # Only payloads that actually hold fields are gc-traverse candidates —
        # a transparent-newtype exception (empty named-field list) reuses its
        # base's payload and is correctly not a "missing traverse" case, so it
        # is excluded from this orientation list to keep it focused.
        "classes_without_traverse": [
            c["rust_name"]
            for c in classes
            if c["traverse_option"] is None
            and not c["has_derive_traverse"]
            and c["fields"]
        ],
        "protocol_impl_counts": dict(sorted(protocol_impls.items())),
        "exposed_function_count": len(exposed_functions),
        "classes": classes,
        "exposed_functions": exposed_functions,
    }
    return report


def main() -> None:
    try:
        target, max_files = parse_common_args(sys.argv[1:])
        result = analyze(target, max_files=max_files)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except Exception as e:  # noqa: BLE001 -- top-level guard, emit JSON error
        json.dump({"error": str(e), "type": type(e).__name__}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
