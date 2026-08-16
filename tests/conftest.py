"""The suite's harness — settings, and the isolation every test relies on.

This file, not the repo-root ``conftest.py``, is the one that must hold
everything: it is the only conftest loaded under *both* invocation styles —
path-based from the repo root (``pytest tests/``) and ``--pyargs
stapel_auth.tests`` from any cwd, which is what CI runs and where the repo root
sits outside the rootdir entirely. ``tests/test_harness_isolation.py`` holds
that line.
"""

import os as _os
import sys as _sys


def _unshadow():
    """Drop the repo root from sys.path — it shadows installed packages.

    Flat package layout (package-dir={"stapel_auth":"."}) puts subdirs like
    openid/ at the repo root, so a repo root on sys.path makes `import openid`
    find that instead of the installed python3-openid, and social_core dies on
    `openid.association`. pytest keeps putting it back: tests/ is a package, so
    importing tests.conftest inserts its basedir — the repo root — again. Hence
    a callable, run at import and again before django.setup(), rather than a
    one-shot line at the top of a conftest.
    """
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    _sys.path = [p for p in _sys.path if _os.path.abspath(p or _os.getcwd()) != root]


_unshadow()


def pytest_configure(config):
    _unshadow()

    # Bootstrap a minimal Celery app so shared_task decorators have a configured
    # app with ALWAYS_EAGER=True before Django settings are loaded.
    from celery import Celery

    _celery = Celery("stapel_auth_test")
    _celery.config_from_object(
        {
            "task_always_eager": True,
            "task_eager_propagates": True,
            "broker_url": "memory://",
            "result_backend": "cache+memory://",
        }
    )
    _celery.set_default()

    from django.conf import settings

    if settings.configured:
        return

    # Single source of truth for this block lives in _codegen_settings.py so the
    # test harness and the contract-emission harness (make contract) can never
    # drift (contract-pipeline.md §3).
    #
    # The MOUNTED urlconf (auth/api/ + v1/), not the bare inner set — see
    # tests/conftest_urls.py for the 2026-07 discovery-404 incident that the old
    # "ROOT_URLCONF=stapel_auth.urls" shortcut hid.
    from stapel_auth._codegen_settings import settings_kwargs

    settings.configure(**settings_kwargs(root_urlconf="stapel_auth.tests.conftest_urls"))
    import django

    _unshadow()
    django.setup()


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_cache():
    """Empty the cache around every test.

    The database rolls back between tests; the cache does not, and since the
    OTP codes, their attempt budgets and the lockout counters all live there
    now, one test's block would otherwise decide the next test's verdict.
    """
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


@pytest.fixture(scope="session")
def django_db_setup(django_test_environment, django_db_blocker):
    from django.test.utils import setup_databases

    with django_db_blocker.unblock():
        setup_databases(verbosity=0, interactive=False)
