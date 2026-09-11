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

#: What ``exchange()`` may do when the grant's address already has a full
#: account (security audit 2026-09-11, M-4):
#:
#: ``"login"``    log them in — the historical behaviour, and the default.
#: ``"refuse"``   refuse the grant. The address keeps its account and its
#:                own sign-in; the issuer sends the plain link instead.
#: ``"step_up"``  log them in only after a second factor, when the account
#:                has one; an account with none is a ``"login"``.
EXISTING_ACCOUNT_POLICIES = ("login", "refuse", "step_up")


class ExistingAccountPolicy(Exception):
    """The grant resolved to an existing account the policy will not log in.

    Distinct from ``exchange() -> None`` on purpose: that answer means the
    GRANT is unusable (unknown, spent, expired) and the caller answers 400.
    This one means the grant was fine and the ACCOUNT is the reason, which is
    a different answer to give the holder and a different line in an audit
    log.
    """

    def __init__(self, user=None):
        super().__init__(self.__class__.__doc__)
        self.user = user


class ExistingAccountRefused(ExistingAccountPolicy):
    """Policy ``refuse``: a grant is not a way into an account that exists."""


class ExistingAccountStepUp(ExistingAccountPolicy):
    """Policy ``step_up``: the account's second factor has to answer first."""


def _existing_account_policy(explicit=None) -> str:
    """Resolve the policy: the argument, else the deployment's setting."""
    if explicit is None:
        from stapel_auth.conf import auth_settings

        explicit = getattr(
            auth_settings, "AUTH_LOGIN_GRANT_EXISTING_ACCOUNTS", "login"
        )
    if explicit not in EXISTING_ACCOUNT_POLICIES:
        raise ValueError(
            f"AUTH_LOGIN_GRANT_EXISTING_ACCOUNTS={explicit!r} is not one of "
            f"{', '.join(EXISTING_ACCOUNT_POLICIES)}"
        )
    return explicit


def _has_second_factor(user) -> bool:
    """Does this account carry a factor a grant can be asked to prove?

    TOTP today — the one factor ``/totp/challenge/verify/`` accepts, which is
    the endpoint a ``step_up`` answer sends the holder to. A passkey is not
    counted here: there is no challenge endpoint that trades one for the
    session this flow is minting.
    """
    from stapel_auth.mfa.services import TOTPService

    try:
        return bool(TOTPService.is_enabled(user))
    except Exception:  # pragma: no cover - a broken factor is not a bypass
        logger.exception("login grant: cannot read the account's TOTP state")
        return True


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
    def exchange(cls, token: str, *, existing_accounts: str | None = None):
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

        ``existing_accounts`` decides what an address that ALREADY has a full
        account may get out of a grant — ``"login"`` (the default and the
        historical behaviour), ``"refuse"`` or ``"step_up"``; see
        :data:`EXISTING_ACCOUNT_POLICIES`. Omitted, it reads
        ``AUTH_LOGIN_GRANT_EXISTING_ACCOUNTS``. The two non-default answers
        raise :class:`ExistingAccountRefused` / :class:`ExistingAccountStepUp`
        rather than returning ``None``: the grant was valid and the account is
        the reason, which is not the same thing to tell the holder as a spent
        token. A guest (anonymous) row is not "an existing account" for this
        purpose — a grant is precisely how a guest stops being one.
        """
        from django.contrib.auth import get_user_model

        policy = _existing_account_policy(existing_accounts)

        data = cls.consume(token)
        if not data:
            return None
        email = data['email']
        User = get_user_model()
        user = User.objects.filter(email=email).first()
        if user is not None:
            if not user.is_active:
                return None
            if policy != 'login' and not getattr(user, 'is_anonymous', False):
                if policy == 'refuse':
                    logger.info('login grant refused: address already has an account')
                    raise ExistingAccountRefused(user)
                if _has_second_factor(user):
                    logger.info('login grant needs a step-up: account has a second factor')
                    raise ExistingAccountStepUp(user)
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
