"""stapel-auth capabilities.json emitter (capability-config.md §1-§2, ETALON).

Emits ``docs/capabilities.json`` — the FOURTH per-module contract artifact,
alongside the ``docs/{schema,flows,errors}.json`` triad and with the same
pipeline discipline: emitted by ``make contract``, drift-gated by
``make contract-check`` / ``tests/test_contract.py``, committed to the repo.

The artifact describes the module's **config axes** (capability-config.md §1):
machine-readable metadata OVER the existing ``STAPEL_AUTH`` settings. Derivable
facts are derived; semantics are curated:

- ``key/kind/default/group`` — introspected from ``stapel_auth.conf.DEFAULTS``
  (the AppSettings-shaped literal dict, §5-A3).
- ``gates.operations`` — from the gate registry in ``stapel_auth.urls``
  (``GATE_REGISTRY``: every URL factory declares its flags + patterns where the
  gating executes), cross-referenced against schema.json operationIds.
- ``curated`` (summary / business_label per axis, module ``provides``,
  ``requires``, ``extension_points``) — the hand-written
  ``docs/capabilities.meta.json``; a missing/extra axis there is a loud
  emission error, never a silent skip.

**Which DEFAULTS keys are axes** (the include rule, documented choice): a key
is a config axis iff ``key.startswith("AUTH_") or key.endswith("_STEP_UP")`` —
the method gates, anonymous, totp and the two step-up policies from the design
§1 list. Everything else in DEFAULTS (TTLs, rate limits, URLs, credentials,
dotted-path seams) is a tuning knob or an extension point, not a CTO-facing
axis. The rule is asserted against the curated meta: both must name the same
key set, so an axis added to conf.py without meta (or vice versa) fails CI.

**Gate composition semantics**: a registry entry's flags compose with OR — its
operations disappear from the URLconf only when ALL flags of the entry are
off. Each axis therefore lists the operations it (co-)gates plus ``co_gates``,
the sibling flags that keep those operations mounted while any of them is on.

This file is a local prototype of the mechanism; it will be lifted into
stapel-tools for the shelf-wide sweep (§5-A6). ``build_capabilities()`` is the
extractable pure core — everything module-specific enters as arguments.

Usage:
    python -m stapel_auth._capabilities --out docs     # part of `make contract`
    (expects <out>/schema.json to exist — emit the triad first)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

#: The canonical mount prefix schema.json paths carry (see codegen_urls.py).
CANONICAL_PREFIX = "/auth/api"

#: Dummy values substituted for ``{param}`` path parameters when probing
#: which URL-factory entry serves a schema path. Tried in order; a path
#: matches an entry if any candidate substitution resolves.
_PROBE_CANDIDATES = ("x", "1", "3fa85f64-5717-4562-b3fc-2c963f66afa6")

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _stable_json(data) -> str:
    """Byte-stable JSON for drift gates — same pinning as stapel_tools.codegen."""
    return json.dumps(data, indent=2, ensure_ascii=False, separators=(",", ": ")) + "\n"


def is_axis(key: str) -> bool:
    """The include rule: method gates + anonymous + totp + step-up policies."""
    return key.startswith("AUTH_") or key.endswith("_STEP_UP")


def axis_group(key: str) -> str:
    """Axis group (capability-config.md §1) — derived from the key shape."""
    if key == "AUTH_ANONYMOUS":
        return "auth.anonymous"
    if key == "AUTH_TOTP":
        return "auth.mfa"
    if key.endswith("_REGISTRATION"):
        return "auth.registration"
    if key.endswith("_LOGIN"):
        return "auth.login"
    if key.endswith("_STEP_UP"):
        return "auth.stepup"
    raise SystemExit(f"capabilities: no axis group rule for key {key!r}")


def _axis_kind(default) -> str:
    if isinstance(default, bool):
        return "bool"
    if isinstance(default, (list, tuple)):
        return "list"
    return "enum"


def _operations_by_entry(schema: dict, registry: dict) -> dict[str, list[str]]:
    """Attribute every schema operation to the registry entry that serves it.

    For each schema path, strip the canonical prefix and resolve the resulting
    URL (with ``{param}`` placeholders substituted) against each entry's own
    patterns. Paths served by no entry (e.g. the co-mounted stapel-gdpr
    endpoints) are simply not attributed — they belong to no auth gate.
    """
    from django.urls.exceptions import Resolver404
    from django.urls.resolvers import RegexPattern, URLResolver

    resolvers = {
        name: URLResolver(RegexPattern(r"^"), list(entry.patterns))
        for name, entry in registry.items()
    }

    def _resolves(resolver, rel_path: str) -> bool:
        for candidate in _PROBE_CANDIDATES:
            probe = re.sub(r"\{[^}]+\}", candidate, rel_path)
            try:
                resolver.resolve(probe)
                return True
            except Resolver404:
                continue
        return False

    ops: dict[str, list[str]] = {name: [] for name in registry}
    for path_key, path_item in schema.get("paths", {}).items():
        if not path_key.startswith(CANONICAL_PREFIX):
            raise SystemExit(
                f"capabilities: schema path {path_key!r} lacks the canonical "
                f"prefix {CANONICAL_PREFIX!r} — wrong schema for this harness?"
            )
        rel = path_key[len(CANONICAL_PREFIX):].lstrip("/")
        for name, resolver in resolvers.items():
            if _resolves(resolver, rel):
                ops[name].extend(
                    op["operationId"]
                    for method, op in path_item.items()
                    if method in _HTTP_METHODS
                )
                break
    return {name: sorted(op_ids) for name, op_ids in ops.items()}


def build_capabilities(
    *,
    module: str,
    version: str,
    defaults: dict,
    registry: dict,
    schema: dict,
    meta: dict,
) -> dict:
    """Assemble the capabilities.json document (pure; extractable to tools)."""
    axis_keys = [key for key in defaults if is_axis(key)]

    meta_axes = meta.get("axes", {})
    missing = [k for k in axis_keys if k not in meta_axes]
    extra = [k for k in meta_axes if k not in axis_keys]
    if missing or extra:
        raise SystemExit(
            "capabilities: curated meta out of sync with conf.py DEFAULTS — "
            f"axes missing from capabilities.meta.json: {missing or 'none'}; "
            f"stale axes in capabilities.meta.json: {extra or 'none'}. "
            "Update docs/capabilities.meta.json to match the axis rule "
            "(AUTH_* or *_STEP_UP keys)."
        )
    for field in ("provides",):
        if not meta.get(field):
            raise SystemExit(f"capabilities: meta field {field!r} is missing/empty")
    for field in ("extension_points", "requires"):
        if not isinstance(meta.get(field), list):
            raise SystemExit(f"capabilities: meta field {field!r} must be a list")

    entry_ops = _operations_by_entry(schema, registry)

    axes = []
    for key in axis_keys:
        curated = meta_axes[key]
        for field in ("summary", "business_label"):
            if not curated.get(field):
                raise SystemExit(
                    f"capabilities: axis {key!r} lacks a non-empty {field!r} "
                    "in docs/capabilities.meta.json"
                )
        gating_entries = [e for e in registry.values() if key in e.flags]
        operations: set[str] = set()
        co_gates: set[str] = set()
        for entry in gating_entries:
            operations.update(entry_ops[entry.name])
            co_gates.update(entry.flags)
        co_gates.discard(key)
        gates = {"operations": sorted(operations), "co_gates": sorted(co_gates)}
        if curated.get("behavior"):
            gates["behavior"] = curated["behavior"]
        axes.append(
            {
                "key": key,
                "kind": _axis_kind(defaults[key]),
                "default": defaults[key],
                "group": axis_group(key),
                "gates": gates,
                "curated": {
                    "summary": curated["summary"],
                    "business_label": curated["business_label"],
                },
            }
        )

    operations_total = sum(
        1
        for path_item in schema.get("paths", {}).values()
        for method in path_item
        if method in _HTTP_METHODS
    )

    return {
        "module": module,
        "version": version,
        "provides": meta["provides"],
        "axes": axes,
        "extension_points": meta["extension_points"],
        "operations_total": operations_total,
        "requires": meta["requires"],
    }


def emit_capabilities(out_dir: Path) -> dict:
    """Emit ``<out_dir>/capabilities.json``; returns the document."""
    repo = Path(__file__).resolve().parent

    pyproject = tomllib.loads((repo / "pyproject.toml").read_text())
    meta_path = repo / "docs" / "capabilities.meta.json"
    if not meta_path.is_file():
        raise SystemExit(
            f"capabilities: curated layer {meta_path} is missing — it is "
            "hand-written (summary/business_label per axis, provides, "
            "requires, extension_points) and must be committed."
        )
    meta = json.loads(meta_path.read_text())

    schema_path = out_dir / "schema.json"
    if not schema_path.is_file():
        raise SystemExit(
            f"capabilities: {schema_path} not found — emit the contract triad "
            "first (python -m stapel_auth._codegen --out {out_dir})."
        )
    schema = json.loads(schema_path.read_text())

    from stapel_auth.conf import DEFAULTS
    from stapel_auth.urls import GATE_REGISTRY

    # Fail closed if the urls module somehow didn't populate the registry.
    if not GATE_REGISTRY:
        raise SystemExit("capabilities: GATE_REGISTRY is empty after urls import")

    doc = build_capabilities(
        module=pyproject["project"]["name"],
        version=pyproject["project"]["version"],
        defaults=DEFAULTS,
        registry=GATE_REGISTRY,
        schema=schema,
        meta=meta,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "capabilities.json").write_text(_stable_json(doc))
    return doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stapel-auth-capabilities",
        description="Emit docs/capabilities.json (fourth contract artifact) "
        "from conf.py DEFAULTS + the urls.py gate registry + schema.json + "
        "the curated docs/capabilities.meta.json.",
    )
    parser.add_argument(
        "--out",
        default="docs",
        help="Output directory; must already contain schema.json (default: docs).",
    )
    args = parser.parse_args(argv)

    # Same single-module Django harness as the triad emitter — the urls module
    # (and therefore the gate registry) needs a configured instance to import.
    from stapel_auth._codegen import _configure

    _configure()

    doc = emit_capabilities(Path(args.out))
    gated = sum(1 for a in doc["axes"] if a["gates"]["operations"])
    print(
        f"stapel-auth capabilities: {len(doc['axes'])} axes ({gated} gating "
        f"operations), {doc['operations_total']} operations total → "
        f"{args.out}/capabilities.json",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
