"""The one place an account is born.

``user.registered`` is what profiles, workspaces and notifications provision
on, so an account created without it has no profile row, no personal
workspace and no welcome mail. The phone-OTP door, the admin broker and SSO
provisioning each created users and never emitted it. Every creation site in
this package goes through :func:`create_account`, which creates the row and
announces it; ``tests/test_account_birth.py`` refuses a bare
``User.objects.create`` anywhere else in the package.

Guest accounts are created by ``User.create_anonymous_user`` and announced at
the mint (``otp/views.py``); promoting a guest keeps its id and is not a
second birth.
"""
from __future__ import annotations

from typing import Any, Callable, Optional


def create_account(
    *,
    request=None,
    language: Optional[str] = None,
    display_name: Optional[str] = None,
    announce: Optional[Callable[[Any], None]] = None,
    **fields: Any,
):
    """Create a user row with *fields* and emit ``user.registered`` for it.

    *announce* replaces the default emitter for a caller that exposes its own
    seam (a view's ``_publish_user_registered``); it is called with the user.
    The emit is best-effort and never fails the creation.
    """
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create(**fields)
    if announce is not None:
        announce(user)
    else:
        from stapel_auth.otp.views import _notify_user_registered

        _notify_user_registered(
            user, request=request, language=language, display_name=display_name
        )
    return user


def users_by_email(email: str, queryset=None):
    """Accounts whose address is *email*, compared case-insensitively.

    ``Alice@x.com`` and ``alice@x.com`` are one mailbox. Exact matching let
    them become two accounts and made a password login raise
    ``MultipleObjectsReturned``. Ordered oldest first, so ``.first()`` is the
    same row every time. Duplicates that already exist are listed by
    ``manage.py auth_email_duplicates``.
    """
    from django.contrib.auth import get_user_model

    qs = queryset if queryset is not None else get_user_model().objects.all()
    return qs.filter(email__iexact=(email or "").strip()).order_by("date_joined", "pk")


def find_user_by_email(email: str, queryset=None):
    """The oldest account whose address is *email* (any case), or ``None``."""
    if not email:
        return None
    return users_by_email(email, queryset).first()


def authenticate_by_email(email: str, password: str):
    """The account at *email* whose password is *password*, or ``None``.

    Tries every case-variant account oldest first, so duplicates left over
    from case-sensitive matching neither 500 nor lock their owners out.
    """
    if not email or not password:
        return None
    for candidate in users_by_email(email):
        if candidate.check_password(password):
            return candidate
    return None


#: Accounts issued by a trusted party under a username (``provision_user``):
#: their email, if any, was set by the issuer, not claimed by a stranger.
_ISSUED_AUTH_TYPES = frozenset({"login"})


def claim_by_proof(user, verified_flag: str, *, save: bool = True) -> bool:
    """An anchor (``is_email_verified`` / ``is_phone_verified``) of an
    EXISTING account was just proven by a code, a link or a provider.

    When the anchor was unproven, whoever put it on the account (a password
    registration typing someone else's address) never showed they hold it.
    The prover does, so the account is theirs: every live session ends, and
    the sign-in credentials the other party could have set (password,
    passkeys) are removed, then the anchor is marked proven. A TOTP device is
    kept: it is a second factor, not a way in, and removing it would let a
    compromised mailbox walk past a legitimate owner's 2FA. Accounts issued
    under a username by a trusted party keep their credentials. Returns True
    when such a takeover happened; a proven anchor is left as it is.
    """
    if getattr(user, verified_flag, False):
        return False
    took_over = getattr(user, "auth_type", "") not in _ISSUED_AUTH_TYPES
    if took_over:
        from stapel_auth.models import PasskeyCredential
        from stapel_auth.sessions.services import SessionService

        SessionService.revoke_all(user)
        if user.has_usable_password():
            user.set_unusable_password()
        PasskeyCredential.objects.filter(user=user).delete()
    setattr(user, verified_flag, True)
    if save:
        user.save()
    return took_over


__all__ = [
    "authenticate_by_email",
    "claim_by_proof",
    "create_account",
    "find_user_by_email",
    "users_by_email",
]
