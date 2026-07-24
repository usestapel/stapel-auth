"""Login grant services (workspaces-org-program §B3).

A login grant is the magic-link mechanic generalized for service-to-service
use: a cache-stored, single-use, short-TTL token that another module mints
**by comm** (``auth.issue_login_grant``) instead of by email, and the holder
exchanges for a full JWT session at ``POST /grant/exchange/``.

Canonical consumer: the workspaces invitation claim flow — the invite email
already proved mailbox ownership, so the grant may carry
``create_if_missing`` and provision a verified email account on exchange
("clicking the link = the account is ready", no second email).

Privacy canon: the grant token and the email are credentials-equivalent —
neither is ever logged, and log lines never combine user identifiers with
token material (same discipline as ``magic_link/services.py``).
"""
import logging
import secrets

logger = logging.getLogger(__name__)


class LoginGrantService:
    """Cache-stored one-shot login grant (create/peek/consume, magic-link mechanic)."""

    TTL = 15 * 60  # 15 minutes, same window as MagicLinkService

    @classmethod
    def _token_key(cls, token: str) -> str:
        return f'login_grant:{token}'

    @classmethod
    def issue(cls, *, email: str, verified_email: bool = True,
              create_if_missing: bool = False, language: str | None = None) -> str:
        """Mint a single-use grant token for *email*.

        The user is NOT created here — resolution (and optional creation)
        happens on exchange, so a grant that is never exchanged leaves no
        account behind and a user registering through another method in the
        meantime is picked up instead of duplicated.
        """
        from django.core.cache import cache
        token = secrets.token_urlsafe(32)
        cache.set(cls._token_key(token), {
            'email': email.strip().lower(),
            'verified_email': bool(verified_email),
            'create_if_missing': bool(create_if_missing),
            'language': language,
        }, cls.TTL)
        logger.info('login grant issued (create_if_missing=%s)', bool(create_if_missing))
        return token

    @classmethod
    def peek(cls, token: str) -> dict | None:
        """Read grant data without consuming it. Returns data or None."""
        from django.core.cache import cache
        return cache.get(cls._token_key(token))

    @classmethod
    def consume(cls, token: str) -> dict | None:
        """Consume the grant (single-use via delete-on-consume). Data or None."""
        from django.core.cache import cache
        key = cls._token_key(token)
        data = cache.get(key)
        if not data:
            return None
        cache.delete(key)
        return data

    @classmethod
    def exchange(cls, token: str):
        """Consume the grant and resolve it to a user.

        Returns ``(user, created)`` or ``None`` when the grant is expired,
        consumed, unknown, or resolves to no usable account:

        * existing active user with the grant's email → ``(user, False)``
          (the grant just logs them in; the invite-flow claim path 409s
          upstream before minting a grant for a registered email, but the
          primitive is safe for both outcomes);
        * no user + ``create_if_missing`` → creates
          ``auth_type="email"``, ``is_email_verified=<verified_email>``,
          unusable password, emits ``user.registered`` (with the grant's
          ``language`` hint for downstream consumers, e.g. profiles) →
          ``(user, True)``;
        * no user, no ``create_if_missing`` → ``None``;
        * user exists but is inactive → ``None``.
        """
        from django.contrib.auth import get_user_model

        data = cls.consume(token)
        if not data:
            return None
        email = data['email']
        User = get_user_model()
        user = User.objects.filter(email=email).first()
        if user is not None:
            if not user.is_active:
                return None
            return user, False
        if not data.get('create_if_missing'):
            return None
        user = User.objects.create(
            email=email,
            auth_type='email',
            is_email_verified=bool(data.get('verified_email', True)),
        )
        user.set_unusable_password()
        user.save(update_fields=['password'])
        from stapel_auth.otp.views import _notify_user_registered
        _notify_user_registered(user, language=data.get('language'))
        return user, True


def issue_login_grant(*, email: str, verified_email: bool = True,
                      create_if_missing: bool = False,
                      language: str | None = None) -> str:
    """Mint a login grant token (module-level seam for the comm function)."""
    return LoginGrantService.issue(
        email=email,
        verified_email=verified_email,
        create_if_missing=create_if_missing,
        language=language,
    )
