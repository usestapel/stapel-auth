"""Path-only shim — the real harness is tests/conftest.py.

Nothing test-facing may live here. CI runs ``python -m pytest --pyargs
stapel_auth.tests``, and under ``--pyargs`` collection is rooted at the *package*
directory: the test node ids start at ``test_*.py``, so this file's directory is
not one of their ancestors and its fixtures are never applied to them. The file
still gets imported, which is what makes the hole quiet — measured 2026-08-16,
``_isolate_cache`` present under ``pytest tests/`` and absent under ``--pyargs``,
worth 18 failures. Its ``pytest_configure`` is worse than useless: whether it or
the package one wins the race decides ``ROOT_URLCONF``, so it is gone.

What must stay: the sys.path surgery below. It only matters when the repo root
is on sys.path, i.e. precisely the path-based runs that do load this file.
``tests/test_harness_isolation.py`` keeps everything else out.
"""
import os as _os
import sys as _sys

# Flat package layout (package-dir={"stapel_auth":"."}) places subdirs like openid/
# at the repo root. pytest adds conftest parent dirs to sys.path, so `import openid`
# resolves to the local openid/ dir instead of the installed python3-openid package.
# Remove the repo root from sys.path before any imports.
_repo_root = _os.path.dirname(_os.path.abspath(__file__))
_sys.path = [p for p in _sys.path if _os.path.abspath(p or _os.getcwd()) != _repo_root]
