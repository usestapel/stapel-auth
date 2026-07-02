"""Public API surface of the stapel_auth package (PEP 562 lazy exports)."""

import pytest

import stapel_auth


def test_all_is_sorted():
    assert stapel_auth.__all__ == sorted(stapel_auth.__all__)


@pytest.mark.parametrize("name", sorted(stapel_auth.__all__))
def test_every_export_resolves_and_is_cached(name):
    value = getattr(stapel_auth, name)
    assert value is not None
    # The resolved value is cached into the module globals so the next
    # access bypasses __getattr__.
    assert vars(stapel_auth)[name] is value
    # __dir__ advertises the export.
    assert name in dir(stapel_auth)


def test_unknown_attribute_raises_attribute_error():
    with pytest.raises(AttributeError, match="does_not_exist"):
        getattr(stapel_auth, "does_not_exist")


def test_exports_are_the_canonical_objects():
    from stapel_auth.conf import auth_settings
    from stapel_auth.oauth_providers import PROVIDER_REGISTRY
    from stapel_auth.urls import get_otp_urls, get_sso_urls

    assert stapel_auth.auth_settings is auth_settings
    assert stapel_auth.PROVIDER_REGISTRY is PROVIDER_REGISTRY
    assert stapel_auth.get_otp_urls is get_otp_urls
    assert stapel_auth.get_sso_urls is get_sso_urls


def test_url_factories_return_patterns_when_enabled():
    patterns = stapel_auth.get_otp_urls(enabled=True)
    assert patterns, "enabled factory should return url patterns"
    assert stapel_auth.get_otp_urls(enabled=False) == []
