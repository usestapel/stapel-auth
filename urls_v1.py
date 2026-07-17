"""URL configuration for stapel-auth.

Composable per-feature urlpatterns factories. Hosts can either

    include('stapel_auth.urls')          # everything (legacy behavior)

or assemble their own URLconf from the factories:

    from stapel_auth.urls import get_otp_urls, get_password_urls
    urlpatterns = [*get_otp_urls(), *get_password_urls(enabled=True)]

Each factory is gated by the corresponding AUTH_* feature flags from
stapel_auth.conf (``enabled=None`` — the default — consults the flags,
``enabled=True/False`` overrides them). This module's own ``urlpatterns``
passes ``enabled=True`` everywhere so ``include('stapel_auth.urls')`` keeps
registering the complete, unchanged URL set (paths and names identical to
the pre-factory monolith) — per-request feature gating stays in the views,
exactly as before.
"""
from typing import NamedTuple

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from stapel_auth.sessions.views import CustomTokenObtainPairView, CustomTokenRefreshView, SessionViewSet
from stapel_auth.otp.views import AuthViewSet, AuthenticatorChangeViewSet
from stapel_auth.oauth.views import OAuthLinkViewSet
from stapel_auth.password.views import PasswordViewSet
from stapel_auth.qr.views import QRAuthViewSet
from stapel_auth.mfa.views import TOTPViewSet, PasskeyViewSet
from stapel_auth.security.views import SecurityStatusViewSet, AuditLogViewSet, RevokeSuspiciousView, AdminAuditLogViewSet
from stapel_auth.magic_link.views import MagicLinkViewSet
from stapel_auth.verification.views import VerificationPreferenceViewSet, VerificationViewSet
from stapel_auth.openid.views import JWKSView, OpenIDConfigurationView, TokenIntrospectView
from stapel_auth.admin.views import ServiceAPIKeyViewSet, AdminUserViewSet, CapabilitiesView, StaffRoleViewSet
from .sso_views import (
    SSODomainLookupView, SAMLMetadataView, SSOLoginView, SAMLACSView,
    OIDCCallbackView, SSOAdminViewSet,
)

__all__ = [
    'get_otp_urls', 'get_anonymous_urls', 'get_password_urls', 'get_oauth_urls',
    'get_sso_urls', 'get_mfa_urls', 'get_qr_urls', 'get_magic_link_urls',
    'get_sessions_urls', 'get_admin_api_urls', 'get_security_urls',
    'get_openid_urls', 'get_verification_urls', 'urlpatterns',
]


def _gate(enabled, *flags) -> bool:
    """Resolve a factory's on/off state: explicit arg wins, else feature flags."""
    if enabled is not None:
        return bool(enabled)
    if not flags:
        return True
    from .conf import auth_settings
    return any(getattr(auth_settings, flag) for flag in flags)


class GateEntry(NamedTuple):
    """One gated URL block: which flags gate which url patterns.

    ``flags`` compose with OR — the block is mounted while ANY flag is on,
    and disappears only when ALL of them are off. Empty flags = always on.
    """
    name: str
    flags: tuple
    patterns: tuple


#: Gate registry (capability-config.md §2 p.2): every URL factory declares
#: ``(name, gating flags, contributed patterns)`` through ``_gated()`` below —
#: the declaration lives exactly where the gating executes, so there is no
#: second truth to drift. Populated at import time (the module-level
#: ``urlpatterns`` composition runs every factory); the capabilities.json
#: emitter (``stapel_auth._capabilities``) snapshots it and cross-references
#: the patterns with docs/schema.json operationIds.
GATE_REGISTRY: dict = {}


def _gated(name, enabled, flags, patterns):
    """Register a gated URL block and apply its gate in one step.

    Records ``(name, flags, patterns)`` in GATE_REGISTRY unconditionally
    (the registry describes the full surface, not the current config), then
    returns ``patterns`` or ``[]`` per ``_gate`` semantics.
    """
    GATE_REGISTRY[name] = GateEntry(name, tuple(flags), tuple(patterns))
    return list(patterns) if _gate(enabled, *flags) else []


def get_sessions_urls(enabled=None):
    """JWT token obtain/refresh + session management. Always on."""
    return _gated('sessions', enabled, (), [
        path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
        path('token/refresh/', CustomTokenRefreshView.as_view({'post': 'refresh_post', 'get': 'refresh_get'}), name='token_refresh'),

        path('sessions/', SessionViewSet.as_view({'get': 'list_sessions', 'delete': 'revoke_all'}), name='sessions'),
        path('sessions/<str:session_id>/', SessionViewSet.as_view({'delete': 'revoke_one'}), name='session_revoke'),
        path('sessions/<str:session_id>/confirm/', SessionViewSet.as_view({'post': 'confirm_session'}), name='session_confirm'),
    ])


def get_anonymous_urls(enabled=None):
    """Anonymous (guest) authentication. Gated by AUTH_ANONYMOUS.

    Its own axis, independent of the email/phone method gates — a deployment
    with all OTP methods off can still serve guests (and vice versa). The
    path is unchanged from when it lived inside the otp factory.
    """
    return _gated('anonymous', enabled, ('AUTH_ANONYMOUS',), [
        path('anonymous/', AuthViewSet.as_view({'post': 'anonymous'}), name='anonymous'),
    ])


def get_otp_urls(enabled=None):
    """Email/phone OTP auth, me/logout/verify, authenticator change.

    Gated by the email/phone login+registration flags. Anonymous auth moved
    to its own factory (get_anonymous_urls) — it is a separate axis.
    """
    return _gated('otp', enabled, (
        'AUTH_EMAIL_LOGIN', 'AUTH_EMAIL_REGISTRATION',
        'AUTH_PHONE_LOGIN', 'AUTH_PHONE_REGISTRATION',
    ), [
        # Email authentication (OTP-based)
        path('email/request/', AuthViewSet.as_view({'post': 'email_request'}), name='email_request'),
        path('email/verify/', AuthViewSet.as_view({'post': 'email_verify'}), name='email_verify'),

        # Phone authentication (OTP-based)
        path('phone/request/', AuthViewSet.as_view({'post': 'phone_request'}), name='phone_request'),
        path('phone/verify/', AuthViewSet.as_view({'post': 'phone_verify'}), name='phone_verify'),

        # User info and logout
        path('me/', AuthViewSet.as_view({'get': 'me'}), name='me'),
        path('logout/', AuthViewSet.as_view({'post': 'logout', 'get': 'logout_get'}), name='logout'),

        # Token verification
        path('verify/', AuthViewSet.as_view({'post': 'verify_token'}), name='verify_token'),

        # ── Authenticator Change: Phone Instant ──
        path('phone/change/instant/request-old/', AuthenticatorChangeViewSet.as_view({'post': 'phone_instant_request_old'}), name='phone_instant_request_old'),
        path('phone/change/instant/verify-old/', AuthenticatorChangeViewSet.as_view({'post': 'phone_instant_verify_old'}), name='phone_instant_verify_old'),
        path('phone/change/instant/request-new/', AuthenticatorChangeViewSet.as_view({'post': 'phone_instant_request_new'}), name='phone_instant_request_new'),
        path('phone/change/instant/verify-new/', AuthenticatorChangeViewSet.as_view({'post': 'phone_instant_verify_new'}), name='phone_instant_verify_new'),

        # ── Authenticator Change: Email Instant ──
        path('email/change/instant/request-old/', AuthenticatorChangeViewSet.as_view({'post': 'email_instant_request_old'}), name='email_instant_request_old'),
        path('email/change/instant/verify-old/', AuthenticatorChangeViewSet.as_view({'post': 'email_instant_verify_old'}), name='email_instant_verify_old'),
        path('email/change/instant/request-new/', AuthenticatorChangeViewSet.as_view({'post': 'email_instant_request_new'}), name='email_instant_request_new'),
        path('email/change/instant/verify-new/', AuthenticatorChangeViewSet.as_view({'post': 'email_instant_verify_new'}), name='email_instant_verify_new'),

        # ── Authenticator Change: Phone Delayed ──
        path('phone/change/delayed/initiate/', AuthenticatorChangeViewSet.as_view({'post': 'phone_delayed_initiate'}), name='phone_delayed_initiate'),
        path('phone/change/delayed/status/', AuthenticatorChangeViewSet.as_view({'get': 'phone_delayed_status'}), name='phone_delayed_status'),
        path('phone/change/delayed/cancel/', AuthenticatorChangeViewSet.as_view({'post': 'phone_delayed_cancel'}), name='phone_delayed_cancel'),

        # ── Authenticator Change: Email Delayed ──
        path('email/change/delayed/initiate/', AuthenticatorChangeViewSet.as_view({'post': 'email_delayed_initiate'}), name='email_delayed_initiate'),
        path('email/change/delayed/status/', AuthenticatorChangeViewSet.as_view({'get': 'email_delayed_status'}), name='email_delayed_status'),
        path('email/change/delayed/cancel/', AuthenticatorChangeViewSet.as_view({'post': 'email_delayed_cancel'}), name='email_delayed_cancel'),
    ])


def get_oauth_urls(enabled=None):
    """OAuth login + server-side authorize/callback flows + account links
    (security-profile: connect/disconnect additional provider accounts)."""
    return _gated('oauth', enabled, ('AUTH_OAUTH_LOGIN', 'AUTH_OAUTH_REGISTRATION'), [
        path('oauth/login/', AuthViewSet.as_view({'post': 'oauth_login'}), name='oauth_login'),
        path('oauth/<str:provider>/authorize/', AuthViewSet.as_view({'get': 'oauth_authorize'}), name='oauth_authorize'),
        path('oauth/<str:provider>/callback/', AuthViewSet.as_view({'get': 'oauth_callback'}), name='oauth_callback'),
        path('oauth/<str:provider>/callback', AuthViewSet.as_view({'get': 'oauth_callback'}), name='oauth_callback_noslash'),
        path('oauth/links/', OAuthLinkViewSet.as_view({'get': 'list_links', 'post': 'link'}), name='oauth_links'),
        path('oauth/links/<str:provider>/', OAuthLinkViewSet.as_view({'delete': 'unlink'}), name='oauth_link_unlink'),
    ])


def get_password_urls(enabled=None):
    """Password login/change/reset/registration."""
    return _gated('password', enabled, ('AUTH_PASSWORD_LOGIN', 'AUTH_PASSWORD_REGISTRATION'), [
        path('password/login/', PasswordViewSet.as_view({'post': 'login'}), name='password_login'),
        path('password/methods/', PasswordViewSet.as_view({'get': 'methods'}), name='password_methods'),
        path('password/change/', PasswordViewSet.as_view({'post': 'change_direct'}), name='password_change'),
        path('password/change/otp/request/', PasswordViewSet.as_view({'post': 'change_otp_request'}), name='password_change_otp_request'),
        path('password/change/otp/verify/', PasswordViewSet.as_view({'post': 'change_otp_verify'}), name='password_change_otp_verify'),
        path('password/reset/email/request/', PasswordViewSet.as_view({'post': 'reset_email_request'}), name='password_reset_email_request'),
        path('password/reset/email/verify/', PasswordViewSet.as_view({'post': 'reset_email_verify'}), name='password_reset_email_verify'),
        path('password/reset/phone/request/', PasswordViewSet.as_view({'post': 'reset_phone_request'}), name='password_reset_phone_request'),
        path('password/reset/phone/verify/', PasswordViewSet.as_view({'post': 'reset_phone_verify'}), name='password_reset_phone_verify'),
        path('password/register/', PasswordViewSet.as_view({'post': 'register'}), name='password_register'),
    ])


def get_qr_urls(enabled=None):
    """QR session-share / login-request auth."""
    return _gated('qr', enabled, ('AUTH_QR_LOGIN',), [
        path('qr/generate/', QRAuthViewSet.as_view({'post': 'generate'}), name='qr_generate'),
        path('qr/<str:key>/status/', QRAuthViewSet.as_view({'get': 'qr_status'}), name='qr_status'),
        path('qr/<str:key>/scan/', QRAuthViewSet.as_view({'get': 'scan'}), name='qr_scan'),
        path('qr/<str:key>/confirm/', QRAuthViewSet.as_view({'post': 'confirm'}), name='qr_confirm'),
        path('qr/<str:key>/reject/', QRAuthViewSet.as_view({'post': 'reject'}), name='qr_reject'),
    ])


def get_mfa_urls(enabled=None):
    """TOTP (gated by AUTH_TOTP) and passkeys (gated by AUTH_PASSKEY_LOGIN)."""
    return _gated('mfa.totp', enabled, ('AUTH_TOTP',), [
        path('totp/setup/', TOTPViewSet.as_view({'post': 'setup'}), name='totp_setup'),
        path('totp/setup/confirm/', TOTPViewSet.as_view({'post': 'confirm_setup'}), name='totp_setup_confirm'),
        path('totp/disable/', TOTPViewSet.as_view({'post': 'disable'}), name='totp_disable'),
        path('totp/disable-otp/request/', TOTPViewSet.as_view({'post': 'disable_request_otp'}), name='totp_disable_otp_request'),
        path('totp/challenge/verify/', TOTPViewSet.as_view({'post': 'challenge_verify'}), name='totp_challenge_verify'),
    ]) + _gated('mfa.passkey', enabled, ('AUTH_PASSKEY_LOGIN',), [
        path('passkey/', PasskeyViewSet.as_view({'get': 'get_list'}), name='passkey_list'),
        path('passkey/register/begin/', PasskeyViewSet.as_view({'post': 'register_begin'}), name='passkey_register_begin'),
        path('passkey/register/complete/', PasskeyViewSet.as_view({'post': 'register_complete'}), name='passkey_register_complete'),
        path('passkey/authenticate/begin/', PasskeyViewSet.as_view({'post': 'auth_begin'}), name='passkey_auth_begin'),
        path('passkey/authenticate/complete/', PasskeyViewSet.as_view({'post': 'auth_complete'}), name='passkey_auth_complete'),
        path('passkey/<str:pk>/', PasskeyViewSet.as_view({'delete': 'destroy'}), name='passkey_destroy'),
    ])


def get_verification_urls(enabled=None):
    """Step-up verification challenge endpoints (stapel_core.verification). Always on."""
    return _gated('verification', enabled, (), [
        # NB: registered before the <str:challenge_id> routes so the literal
        # "preferences" segment is not swallowed by the challenge_id pattern.
        path('verification/preferences/', VerificationPreferenceViewSet.as_view({'get': 'list_preferences', 'put': 'set_preference'}), name='verification_preferences'),
        path('verification/<str:challenge_id>/', VerificationViewSet.as_view({'get': 'info'}), name='verification_info'),
        path('verification/<str:challenge_id>/initiate/', VerificationViewSet.as_view({'post': 'initiate'}), name='verification_initiate'),
        path('verification/<str:challenge_id>/complete/', VerificationViewSet.as_view({'post': 'complete'}), name='verification_complete'),
    ])


def get_magic_link_urls(enabled=None):
    """Magic link request/verify."""
    return _gated('magic_link', enabled, ('AUTH_MAGIC_LINK_LOGIN',), [
        path('magic/request/', MagicLinkViewSet.as_view({'post': 'request_link'}), name='magic_request'),
        path('magic/verify/', MagicLinkViewSet.as_view({'get': 'verify'}), name='magic_verify'),
    ])


def get_sso_urls(enabled=None):
    """Enterprise SSO: SAML SP + OIDC RP + org admin CRUD."""
    return _gated('sso', enabled, ('AUTH_SSO_LOGIN', 'AUTH_SSO_REGISTRATION'), [
        path('sso/lookup/', SSODomainLookupView.as_view(), name='sso_lookup'),
        # Unified login entry point (SAML or OIDC, dispatched by org config)
        path('sso/<slug:slug>/login/', SSOLoginView.as_view(), name='sso_login'),
        # SAML ACS + metadata (backend-facing, IdP posts here)
        path('sso/<slug:slug>/saml/metadata/', SAMLMetadataView.as_view(), name='sso_saml_metadata'),
        path('sso/<slug:slug>/saml/acs/', SAMLACSView.as_view(), name='sso_saml_acs'),
        # OIDC callback (backend-facing, IdP redirects here)
        path('sso/<slug:slug>/oidc/callback/', OIDCCallbackView.as_view(), name='sso_oidc_callback'),
        # Admin CRUD
        path('sso/orgs/', SSOAdminViewSet.as_view({'get': 'list_orgs', 'post': 'create_org'}), name='sso_orgs'),
        path('sso/orgs/<slug:slug>/', SSOAdminViewSet.as_view({'get': 'get_org', 'patch': 'update_org', 'delete': 'delete_org'}), name='sso_org'),
        path('sso/orgs/<slug:slug>/config/', SSOAdminViewSet.as_view({'put': 'upsert_config', 'patch': 'upsert_config'}), name='sso_org_config'),
    ])


def get_security_urls(enabled=None):
    """Security status, audit log, suspicious-session revoke. Always on."""
    return _gated('security', enabled, (), [
        path('security/status/', SecurityStatusViewSet.as_view({'get': 'status'}), name='security_status'),
        path('security/audit/', AuditLogViewSet.as_view({'get': 'get_log'}), name='security_audit'),
        path('security/revoke-suspicious/', RevokeSuspiciousView.as_view(), name='revoke_suspicious'),
    ])


def get_openid_urls(enabled=None):
    """JWKS / OpenID discovery / token introspection. Always on."""
    return _gated('openid', enabled, (), [
        path('.well-known/jwks.json', JWKSView.as_view({'get': 'jwks'}), name='jwks'),
        path('.well-known/openid-configuration', OpenIDConfigurationView.as_view({'get': 'openid_configuration'}), name='openid-configuration'),
        path('oauth2/introspect/', TokenIntrospectView.as_view(), name='oauth2_introspect'),
    ])


def get_admin_api_urls(enabled=None):
    """Service keys, capabilities, admin user broker, admin audit. Always on."""
    router = DefaultRouter(trailing_slash=False)
    router.register(r'service-keys', ServiceAPIKeyViewSet, basename='service-keys')
    return _gated('admin_api', enabled, (), [
        # Router URLs
        path('', include(router.urls)),

        # ── Auth Capabilities ──────────────────────────────────────────────────
        path('capabilities/', CapabilitiesView.as_view(), name='capabilities'),

        # ── Admin User Broker ─────────────────────────────────────────────────
        path('admin-users/', AdminUserViewSet.as_view({'post': 'create_user'}), name='admin-users'),

        # ── Admin Audit Log ───────────────────────────────────────────────────
        path('admin/audit/', AdminAuditLogViewSet.as_view({'get': 'list_logs'}), name='admin-audit'),

        # ── Staff Roles (admin-suite AS-2; auth is the single writer, A2) ────
        path('staff-roles/', StaffRoleViewSet.as_view({'get': 'list_assignments', 'post': 'assign'}), name='staff-roles'),
        path('staff-roles/<uuid:assignment_id>/', StaffRoleViewSet.as_view({'delete': 'revoke'}), name='staff-role-detail'),
    ])


# Full URL set — identical paths and names to the pre-factory monolithic
# urls.py. Feature flags are enforced per-request inside the views (403),
# exactly as before; pass the factories to your own URLconf if you want
# disabled features to 404 instead.
urlpatterns = (
    get_sessions_urls(enabled=True)
    + get_otp_urls(enabled=True)
    + get_anonymous_urls(enabled=True)
    + get_oauth_urls(enabled=True)
    + get_admin_api_urls(enabled=True)
    + get_password_urls(enabled=True)
    + get_qr_urls(enabled=True)
    + get_security_urls(enabled=True)
    + get_mfa_urls(enabled=True)
    + get_magic_link_urls(enabled=True)
    + get_sso_urls(enabled=True)
    + get_openid_urls(enabled=True)
    + get_verification_urls(enabled=True)
)
