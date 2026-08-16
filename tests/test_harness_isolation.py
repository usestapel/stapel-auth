"""The repo-root conftest must define nothing — CI never loads it.

CI runs ``python -m pytest --pyargs stapel_auth.tests`` (publish.yml). Under
``--pyargs`` collection is rooted at the package directory, so test node ids
start at ``test_*.py`` and the repo-root ``conftest.py`` is not an ancestor of
any of them: it is imported, but none of its fixtures reach a test. On
2026-08-16 the autouse cache-isolation fixture lived there, so under CI it never
ran: OTP codes, attempt budgets and lockout counters leaked between tests and 18
of them failed with 429s and stale-code mismatches — while ``pytest tests/``
from the repo root stayed green, where the same file *is* an ancestor. Two
harnesses, two verdicts, and the red one was the one that gated releases.

Pinning the invariant rather than the symptom: no definitions in the root
conftest at all. Fixtures, hooks and helpers belong in tests/conftest.py, which
both invocation styles load.
"""
import ast
from pathlib import Path

import pytest

_ROOT_CONFTEST = Path(__file__).resolve().parent.parent / "conftest.py"


@pytest.mark.skipif(
    not _ROOT_CONFTEST.exists(),
    reason="installed as a wheel — the repo-root conftest is not shipped",
)
def test_root_conftest_defines_nothing():
    tree = ast.parse(_ROOT_CONFTEST.read_text())
    defined = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert defined == [], (
        "conftest.py at the repo root defines {}, but CI runs `--pyargs "
        "stapel_auth.tests`, where collection is rooted at the package "
        "directory and nothing in this file reaches a test. Move it to "
        "tests/conftest.py, which both invocation styles load.".format(defined)
    )
