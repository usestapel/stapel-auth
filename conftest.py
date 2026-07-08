import os as _os
import sys as _sys

# Flat package layout (package-dir={"stapel_auth":"."}) places subdirs like openid/
# at the repo root. pytest adds conftest parent dirs to sys.path, so `import openid`
# resolves to the local openid/ dir instead of the installed python3-openid package.
# Remove the repo root from sys.path before any imports.
_repo_root = _os.path.dirname(_os.path.abspath(__file__))
_sys.path = [p for p in _sys.path if _os.path.abspath(p or _os.getcwd()) != _repo_root]


def pytest_configure(config):
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
    # drift (contract-pipeline.md §3). Tests keep the bare mount + no spectacular,
    # exactly as before the extraction.
    from stapel_auth._codegen_settings import settings_kwargs

    settings.configure(**settings_kwargs())
    import django
    django.setup()


import pytest  # noqa: E402


@pytest.fixture(scope="session")
def django_db_setup(django_test_environment, django_db_blocker):
    from django.test.utils import setup_databases
    with django_db_blocker.unblock():
        setup_databases(verbosity=0, interactive=False)
