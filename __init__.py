"""stapel-auth — pluggable authentication for Django.

Public API of the ``stapel_auth`` package, exported lazily (PEP 562) so that
importing the package itself stays side-effect free: the runtime settings
object (``auth_settings``), the per-feature URL-pattern factories from
``stapel_auth.urls`` and the OAuth provider registry (``PROVIDER_REGISTRY``).
"""

from importlib import import_module

# name -> (relative module, attribute) — resolved on first attribute access.
_LAZY_EXPORTS = {
    "auth_settings": (".conf", "auth_settings"),
    "PROVIDER_REGISTRY": (".oauth_providers", "PROVIDER_REGISTRY"),
    "get_admin_api_urls": (".urls", "get_admin_api_urls"),
    "get_magic_link_urls": (".urls", "get_magic_link_urls"),
    "get_mfa_urls": (".urls", "get_mfa_urls"),
    "get_oauth_urls": (".urls", "get_oauth_urls"),
    "get_openid_urls": (".urls", "get_openid_urls"),
    "get_otp_urls": (".urls", "get_otp_urls"),
    "get_password_urls": (".urls", "get_password_urls"),
    "get_qr_urls": (".urls", "get_qr_urls"),
    "get_security_urls": (".urls", "get_security_urls"),
    "get_sessions_urls": (".urls", "get_sessions_urls"),
    "get_sso_urls": (".urls", "get_sso_urls"),
}

__all__ = sorted(_LAZY_EXPORTS)


def __getattr__(name):
    """PEP 562 lazy exports: resolve, cache into globals(), return."""
    try:
        module_path, attr = _LAZY_EXPORTS[name]
    except KeyError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None
    value = getattr(import_module(module_path, __name__), attr)
    globals()[name] = value  # cache — __getattr__ is skipped next time
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
