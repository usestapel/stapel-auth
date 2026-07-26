"""URL configuration used only during tests.

Mounts the module through its **root** urlconf (``stapel_auth.urls``) — the
same ``include`` every host uses — so the suite exercises the *mounted*
contract, host prefix and version segment and all: ``/auth/api/v1/<route>``.

Why this matters (incident, 2026-07): ``conftest.py`` used to point
ROOT_URLCONF straight at the inner ``stapel_auth.urls_v1``, skipping both the
host mount and the ``v1/`` prefix ``urls.py`` contributes. Nothing in the
suite ever crossed the mount, so nothing could notice that the OIDC discovery
document advertised ``/auth/api/v1/auth/token/`` (a second, non-existent
``auth/`` segment) and ``/auth/.well-known/jwks.json`` — the shapes of the
pre-library monolith. Every external OIDC client that read the document
walked into a 404 while the suite stayed green. Same class of bug as the
stapel-workspaces pre-v1 incident a week earlier.

Mount through the root urlconf only; the advertised URLs are pinned by
``tests/test_openid_discovery_contract.py``. Tests that deliberately exercise
a partial URL set (feature-gated factories) still build their own urlconf and
mount it at root — that is a different question and stays as it is.

The host prefix (``auth/api/``) reproduces the deployed mount (URL_PREFIX =
``auth/``); the ``v1/...`` tail is what this module owns and ships.
"""

from django.urls import include, path

urlpatterns = [
    path("auth/api/", include("stapel_auth.urls")),
]
