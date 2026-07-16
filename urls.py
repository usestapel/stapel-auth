"""Root URLconf for stapel-auth — v1 canon mount (api-versioning.md §2, §6).

Canon: ``/<mod>/api/v1/...`` — the version segment sits right after ``api/``.
Hosts keep mounting ``include('stapel_auth.urls')`` under their ``.../api/``
prefix; this module contributes the mandatory ``v1/`` sub-prefix. The actual
URL set (paths inside unchanged) and the per-feature factories live in
``urls_v1.py`` — the factories and the gate registry are re-exported here so
``from stapel_auth.urls import ...`` keeps working for hosts assembling their
own URLconf (mount the factory output under your own ``v1/`` prefix).
"""
from django.urls import include, path

from stapel_auth.urls_v1 import (  # noqa: F401  (re-export, see docstring)
    GATE_REGISTRY,
    get_admin_api_urls,
    get_anonymous_urls,
    get_magic_link_urls,
    get_mfa_urls,
    get_oauth_urls,
    get_openid_urls,
    get_otp_urls,
    get_password_urls,
    get_qr_urls,
    get_security_urls,
    get_sessions_urls,
    get_sso_urls,
    get_verification_urls,
)

__all__ = [
    'GATE_REGISTRY',
    'get_otp_urls', 'get_anonymous_urls', 'get_password_urls', 'get_oauth_urls',
    'get_sso_urls', 'get_mfa_urls', 'get_qr_urls', 'get_magic_link_urls',
    'get_sessions_urls', 'get_admin_api_urls', 'get_security_urls',
    'get_openid_urls', 'get_verification_urls', 'urlpatterns',
]

urlpatterns = [
    path('v1/', include('stapel_auth.urls_v1')),
]
