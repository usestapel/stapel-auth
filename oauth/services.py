"""OAuth service classes for authentication routing and capabilities."""
import logging

logger = logging.getLogger(__name__)

#: Allowed values for AUTH_<METHOD>_PLACEMENT (conf.py) — anything else falls
#: back to 'main' rather than emitting a value the frontend doesn't know how
#: to render.
_VALID_PLACEMENTS = ('main', 'overflow', 'bottom')

#: method id -> (conf.py placement key, fixed priority order). Order mirrors
#: the house default sign-in priority (most universal first, password last —
#: same ordering the stapel-react default skin ships as DEFAULT_CHANNEL_PRIORITY)
#: so a host that only overrides *_PLACEMENT still gets a sane within-zone order.
_METHOD_ORDER = {
    'email':      ('AUTH_EMAIL_PLACEMENT', 0),
    'phone':      ('AUTH_PHONE_PLACEMENT', 1),
    'passkey':    ('AUTH_PASSKEY_PLACEMENT', 2),
    'oauth':      ('AUTH_OAUTH_PLACEMENT', 3),
    'sso':        ('AUTH_SSO_PLACEMENT', 4),
    'qr':         ('AUTH_QR_PLACEMENT', 5),
    'magic_link': ('AUTH_MAGIC_LINK_PLACEMENT', 6),
    'password':   ('AUTH_PASSWORD_PLACEMENT', 7),
}

#: Methods that always redirect to an external party regardless of placement
#: (owner directive: "overflow/bottom -> modal OR redirect" — oauth/sso are
#: the redirect half of that "or").
_ALWAYS_REDIRECT = frozenset({'oauth', 'sso'})


def _method_info(method_id: str, enabled: bool):
    """Build one ``AuthMethodInfo`` for a login method (capabilities.py contract).

    ``interaction`` is derived, not configured: 'main' placement renders
    inline in the tab; everything else opens a modal, except oauth/sso which
    always redirect to the provider (client rule from the owner directive).
    """
    from stapel_auth.conf import auth_settings
    from stapel_auth.oauth.dto import AuthMethodInfo
    from stapel_auth.oauth.icons import METHOD_ICONS

    conf_key, order = _METHOD_ORDER[method_id]
    placement = getattr(auth_settings, conf_key)
    if placement not in _VALID_PLACEMENTS:
        placement = 'main'

    if method_id in _ALWAYS_REDIRECT:
        interaction = 'redirect'
    elif placement == 'main':
        interaction = 'inline'
    else:
        interaction = 'modal'

    return AuthMethodInfo(
        id=method_id,
        enabled=enabled,
        placement=placement,
        order=order,
        interaction=interaction,
        icon_svg=METHOD_ICONS[method_id],
    )


class OAuthService:
    """Service for OAuth authentication — routes through provider registry."""

    def get_user_data(self, provider, access_token):
        """Fetch user data from the given OAuth provider."""
        from stapel_core.oauth import get_provider
        p = get_provider(provider)
        if not p:
            logger.error(f"Unsupported OAuth provider: {provider}")
            return None
        try:
            return p.get_user_data(access_token)
        except Exception as e:
            logger.error(f"Failed to get user data from {provider}: {e}")
            return None


class OAuthLinkService:
    """Manage additional OAuth accounts connected to an existing user
    (security-profile inventory: GET/link/unlink, distinct from the
    login/registration OAuth flow in ``AuthViewSet``).

    ``User.oauth_provider``/``oauth_id`` (the provider a user originally
    registered/logged in with) is reported as the ``primary`` entry but is
    never written/removed here — only ``LinkedOAuthAccount`` rows (secondary
    links) are managed by ``link``/``unlink``.
    """

    @staticmethod
    def list_links(user):
        """Every connected provider account: the primary one (if set) first,
        then secondary links most-recently-linked first."""
        from stapel_auth.models import LinkedOAuthAccount
        from stapel_auth.oauth.dto import LinkedOAuthAccountDTO

        links = []
        if user.oauth_provider:
            links.append(
                LinkedOAuthAccountDTO(
                    provider=user.oauth_provider,
                    email=user.email or None,
                    display_name='',
                    linked_at=user.created_at.isoformat() if getattr(user, 'created_at', None) else None,
                    primary=True,
                )
            )
        for row in LinkedOAuthAccount.objects.filter(user=user).order_by('-linked_at'):
            links.append(
                LinkedOAuthAccountDTO(
                    provider=row.provider,
                    email=row.email,
                    display_name=row.display_name,
                    linked_at=row.linked_at.isoformat(),
                    primary=False,
                )
            )
        return links

    @staticmethod
    def link(user, provider, access_token):
        """Verify *access_token* against *provider* and attach it to *user*.

        Returns ``(LinkedOAuthAccount, error_code)`` — exactly one is not
        ``None``. Error codes: ``already_linked`` (this provider is already
        connected — as primary or secondary), ``linked_elsewhere`` (the
        provider account belongs to a different user), ``failed`` (token
        verification failed).
        """
        from stapel_auth.models import LinkedOAuthAccount

        if user.oauth_provider == provider:
            return None, 'already_linked'
        if LinkedOAuthAccount.objects.filter(user=user, provider=provider).exists():
            return None, 'already_linked'

        user_data = OAuthService().get_user_data(provider, access_token)
        if not user_data:
            return None, 'failed'

        provider_user_id = str(user_data.id)
        # Same provider account already claimed by primary linkage elsewhere,
        # or by another user's secondary link.
        other_user_model = type(user)
        if other_user_model.objects.filter(
            oauth_provider=provider, oauth_id=provider_user_id
        ).exclude(pk=user.pk).exists():
            return None, 'linked_elsewhere'
        if LinkedOAuthAccount.objects.filter(
            provider=provider, provider_user_id=provider_user_id
        ).exclude(user=user).exists():
            return None, 'linked_elsewhere'

        row, _created = LinkedOAuthAccount.objects.update_or_create(
            user=user, provider=provider,
            defaults={
                'provider_user_id': provider_user_id,
                'email': user_data.email or None,
                'display_name': getattr(user_data, 'username', '') or '',
            },
        )
        return row, None

    @staticmethod
    def unlink(user, provider):
        """Remove a secondary link for *provider*.

        Returns one of ``'ok'``, ``'not_found'`` (no such secondary link —
        including when *provider* is only the primary, immutable here) or
        ``'last_method'`` (removing it would leave the account with no way
        to sign in).
        """
        from stapel_auth.models import LinkedOAuthAccount

        try:
            row = LinkedOAuthAccount.objects.get(user=user, provider=provider)
        except LinkedOAuthAccount.DoesNotExist:
            return 'not_found'

        has_password = user.has_usable_password()
        has_primary_oauth = bool(user.oauth_provider)
        other_links = LinkedOAuthAccount.objects.filter(user=user).exclude(pk=row.pk).exists()
        has_passkey = False
        try:
            from stapel_auth.models import PasskeyCredential
            has_passkey = PasskeyCredential.objects.filter(user=user, is_active=True).exists()
        except Exception:
            pass
        if not (has_password or has_primary_oauth or other_links or has_passkey):
            return 'last_method'

        row.delete()
        return 'ok'


class AuthCapabilitiesService:
    """Builds the auth capabilities response based on current settings."""

    @staticmethod
    def get_capabilities():
        from stapel_auth.conf import auth_settings
        from stapel_auth.mfa.services import TOTPService
        from stapel_auth.oauth.dto import (
            AuthCapabilities,
            LoginCapabilities,
            MFACapabilities,
            OAuthProviderInfo,
            OtpMeta,
            RegistrationCapabilities,
        )
        from stapel_auth.oauth_providers import get_enabled_providers
        from stapel_auth.otp.services import OTP_CODE_LENGTH

        s = auth_settings
        phone_real = not s.USE_MOCK_SMS_OTP
        email_real = not s.USE_MOCK_EMAIL_OTP
        oauth_infos = [
            OAuthProviderInfo(id=p.id, name=p.display_name)
            for p in get_enabled_providers()
        ]
        return AuthCapabilities(
            registration=RegistrationCapabilities(
                phone=s.AUTH_PHONE_REGISTRATION and phone_real,
                email=s.AUTH_EMAIL_REGISTRATION and email_real,
                password=s.AUTH_PASSWORD_REGISTRATION,
                oauth=oauth_infos if s.AUTH_OAUTH_REGISTRATION else [],
                sso=s.AUTH_SSO_REGISTRATION,
                anonymous=s.AUTH_ANONYMOUS,
            ),
            login=LoginCapabilities(
                phone=s.AUTH_PHONE_LOGIN and phone_real,
                email=s.AUTH_EMAIL_LOGIN and email_real,
                password=s.AUTH_PASSWORD_LOGIN,
                oauth=oauth_infos if s.AUTH_OAUTH_LOGIN else [],
                sso=s.AUTH_SSO_LOGIN,
                qr=s.AUTH_QR_LOGIN,
                passkey=s.AUTH_PASSKEY_LOGIN,
                magic_link=s.AUTH_MAGIC_LINK_LOGIN,
            ),
            mfa=MFACapabilities(
                totp=s.AUTH_TOTP,
                passkey=s.AUTH_PASSKEY_LOGIN,
            ),
            methods=[
                _method_info('email', s.AUTH_EMAIL_LOGIN and email_real),
                _method_info('phone', s.AUTH_PHONE_LOGIN and phone_real),
                _method_info('password', s.AUTH_PASSWORD_LOGIN),
                _method_info('passkey', s.AUTH_PASSKEY_LOGIN),
                _method_info('qr', s.AUTH_QR_LOGIN),
                _method_info('magic_link', s.AUTH_MAGIC_LINK_LOGIN),
                _method_info('sso', s.AUTH_SSO_LOGIN),
                _method_info('oauth', bool(oauth_infos) and s.AUTH_OAUTH_LOGIN),
            ],
            otp=OtpMeta(
                email_code_length=OTP_CODE_LENGTH,
                phone_code_length=OTP_CODE_LENGTH,
                totp_code_length=TOTPService.CODE_LENGTH,
                ttl_seconds=s.OTP_TTL,
                resend_cooldown_seconds=s.OTP_RESEND_COOLDOWN,
            ),
        )
