"""stapel-auth contract-emission harness (contract-pipeline.md §2-3, ETALON).

Emits the module's own contract triad into ``docs/`` from a single-module
``{auth + gdpr + core}`` Django instance mounted at the canonical ``auth/api/``
prefix:

  docs/schema.json   drf-spectacular OpenAPI, this module only, canonical prefix
  docs/flows.json    generate_flow_docs machine artifact, canonical-prefix paths
  docs/errors.json   generate_error_keys registry (already the etalon)

This is the reference implementation the other four pair-backends copy. The
*mechanism* is stapel_tools.codegen (unchanged, shared); this file is the thin
per-module *config* that wires the module's settings + canonical mount into it.

Usage:
    python -m stapel_auth._codegen --out docs        # `make contract`
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _configure() -> None:
    """Configure + boot the single-module Django instance for emission."""
    # Flat package layout (package-dir={"stapel_auth":"."}) puts subdirs like
    # openid/ at the repo root; `python -m` prepends cwd to sys.path, so a repo-root
    # entry would shadow python3-openid with the local openid/ dir. Strip it, the
    # same guard conftest.py applies for the test run.
    repo_root = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != repo_root]

    # Bootstrap an eager Celery app before Django setup so shared_task decorators
    # bind to a configured app (mirrors conftest.pytest_configure).
    from celery import Celery

    celery = Celery("stapel_auth_codegen")
    celery.config_from_object(
        {
            "task_always_eager": True,
            "task_eager_propagates": True,
            "broker_url": "memory://",
            "result_backend": "cache+memory://",
        }
    )
    celery.set_default()

    from django.conf import settings

    if not settings.configured:
        from stapel_auth._codegen_settings import settings_kwargs

        settings.configure(
            **settings_kwargs(root_urlconf="stapel_auth.codegen_urls", contract=True)
        )

    import django

    django.setup()

    # drf-spectacular froze its settings singleton at import time (before this
    # harness ran configure()), so it is on drf defaults — the same state the
    # monolith emits under. The one knob to force is SCHEMA_PATH_PREFIX: left None,
    # drf derives the operationId prefix from the common path of all endpoints —
    # "/" across the multi-module monolith (operationIds keep the mount segment,
    # auth_api_*), but "/auth/api" in a single-module harness (which would strip it
    # to bare anonymous_create). Pin it to the monolith's common prefix so the
    # operationIds are byte-identical; SCHEMA_PATH_PREFIX_TRIM stays False (default)
    # so the path *keys* keep /auth/api/ on both sides.
    from drf_spectacular.settings import spectacular_settings

    from stapel_auth._codegen_settings import CODEGEN_SCHEMA_PATH_PREFIX

    spectacular_settings.SCHEMA_PATH_PREFIX = CODEGEN_SCHEMA_PATH_PREFIX


def _require_python_312() -> None:
    """Abort emission if not running the pinned 3.12 interpreter.

    drf-spectacular's rendering of component descriptions (``Optional[X]`` vs
    ``X | None``) depends on the Python **minor** version — contracts emitted
    on anything other than 3.12 (the CI/monolith pin) produce false diffs
    against the committed docs/*.json. Emission must never proceed on the
    wrong minor.
    """
    if sys.version_info[:2] != (3, 12):
        got = f"{sys.version_info.major}.{sys.version_info.minor}"
        raise SystemExit(
            f"stapel-auth contract emission ABORTED: running Python {got}, "
            "but contracts must be emitted on Python 3.12 (the CI/monolith "
            "pin). drf-spectacular renders component descriptions "
            "(Optional[X] vs X | None) differently across Python minor "
            "versions, so emitting on any other minor produces false diffs "
            "against the committed docs/*.json. Re-run under a 3.12 "
            "interpreter."
        )


def main(argv: list[str] | None = None) -> int:
    _require_python_312()

    parser = argparse.ArgumentParser(
        prog="stapel-auth-contract",
        description="Emit this module's contract triad (schema.json + flows.json "
        "+ errors.json) into --out, canonical /auth/api/ prefix.",
    )
    parser.add_argument(
        "--out",
        default="docs",
        help="Output directory for the triad (default: docs).",
    )
    args = parser.parse_args(argv)

    _configure()

    # Reuse the shared mechanism's byte-stable emitters (contract-pipeline.md §2:
    # "the single-module harness already exists"). We call the three triad
    # emitters directly rather than generate(), which would also emit the
    # features/ Gherkin bundle — a separate concern auth ships via docs/flows/.
    from stapel_tools.codegen import emit_errors, emit_flows, emit_schema

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    paths = emit_schema(out / "schema.json")
    flows = emit_flows(out / "flows.json")
    errors = emit_errors(out / "errors.json")

    print(
        f"stapel-auth contract: {paths} paths, {flows} flows, {errors} error keys "
        f"→ {out}/",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
