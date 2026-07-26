"""Canonical-prefix URLconf for contract emission (contract-pipeline.md §2).

The monolith aggregate — and therefore every frontend projection and
``MANIFEST_TAGPREFIX="/auth/api/v1/"`` — serves auth under its canonical
public API prefix, ``/auth/api/v1/password/login/`` (v1 canon,
api-versioning.md §2: the module's own root urls.py contributes the ``v1/``
segment, so the host mount string stays ``auth/api/``). Emitting from any
other mount is the repoint bug.

``tests/conftest_urls.py`` mounts the module at the same ``auth/api/`` for
the test suite: until 2026-07 the suite ran on the bare inner urlconf, the
two artifact sets disagreed (docs/flows.json canonical vs docs/flows/ bare),
and the OIDC discovery document shipped URLs that resolved nowhere.

This URLconf reproduces the monolith mount **exactly** (svc-app/core/urls.py
lines 36-37: auth *and* gdpr both under ``auth/api/``), so drf-spectacular emits
``/auth/api/v1/...`` paths (and the matching ``auth_api_*`` operationIds) and
``generate_flow_docs`` resolves flow endpoints to the same. Getting this prefix
exact is the make-or-break for a zero-diff repoint (contract-pipeline.md §2, §9).
"""
from django.conf.urls import include
from django.urls import path

urlpatterns = [
    path("auth/api/", include("stapel_auth.urls")),
    path("auth/api/", include("stapel_gdpr.urls")),
]
