"""``user.signed_up``: the one self-serve registration milestone per account.

``user.registered`` fires at account CREATION, guests included, and is what
workspaces provision on. It cannot answer "a person signed up": a guest is
created long before it gives an address, and the guest's promotion on the
same row announces nothing there. ``user.signed_up`` is that answer — emitted
when a self-serve door leaves an account holding a sign-in identity (an
e-mail, a phone, an OAuth identity, or a password where
``AUTH_PASSWORD_DEANONYMIZES`` makes one an identity), whether the row is new
or a promoted guest.

Not a sign-up: the guest enrolment itself, org provisioning
(``auth.provision_user``), login grants, enterprise SSO, staff-created
accounts, and every LOGGED_IN / MERGED / MODIFIED answer.
``tests/test_user_signed_up.py`` holds the door list against the code.

Consent: the payload carries the visitor's advertising consent as the HOST
reads it, through ``AUTH_SIGNUP_CONSENT_RESOLVER``. The library ships no
reader — which cookie or header means what is the deployment's own business.
"""
from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass

from .events import EVENT_USER_SIGNED_UP

logger = logging.getLogger(__name__)

AD_CONSENT_VALUES = ("granted", "denied", "unknown")


@dataclass(frozen=True)
class SignupConsent:
    """A resolver's answer: the consent state and what decided it.

    ``ad_consent`` is one of ``"granted"``, ``"denied"``, ``"unknown"``.
    ``source`` is free text naming the signal that decided (kept with the
    consent record), e.g. ``"banner_accepted"`` or ``"gpc_header"``.
    """

    ad_consent: str
    source: str = ""


NO_RESOLVER = SignupConsent("unknown", "no_resolver")
NO_REQUEST = SignupConsent("unknown", "no_request")
RESOLVER_ERROR = SignupConsent("denied", "resolver_error")


def resolve_signup_consent(request) -> SignupConsent:
    """Ask the host's ``AUTH_SIGNUP_CONSENT_RESOLVER`` about *request*.

    Never raises. A resolver that raises, cannot be imported, or answers
    something outside the vocabulary yields ``denied`` — the answer that can
    never be reported against the visitor — and the registration goes on.
    """
    from django.db import transaction
    from django.utils.module_loading import import_string

    from .conf import auth_settings

    if request is None:
        return NO_REQUEST
    path = auth_settings.AUTH_SIGNUP_CONSENT_RESOLVER
    if not path:
        return NO_RESOLVER
    try:
        resolver = import_string(path) if isinstance(path, str) else path
        # A savepoint, so a resolver whose query fails cannot poison the
        # request transaction the registration still has to commit.
        with transaction.atomic():
            answer = resolver(request)
        if isinstance(answer, SignupConsent):
            consent = answer
        else:
            ad_consent, source = answer
            consent = SignupConsent(ad_consent, source)
        if consent.ad_consent not in AD_CONSENT_VALUES:
            raise ValueError(f"unknown ad_consent {consent.ad_consent!r}")
        return SignupConsent(consent.ad_consent, str(consent.source or ""))
    except Exception:
        logger.exception("AUTH_SIGNUP_CONSENT_RESOLVER %r failed; recording denied", path)
        return RESOLVER_ERROR


def notify_user_signed_up(user, *, request=None, was_guest: bool) -> None:
    """Emit ``user.signed_up`` for *user* unless the account already has one.

    Called by a door after the save that made the account a signed-up one.
    Best-effort exactly like ``user.registered``: the marker row and the emit
    share one savepoint, a failure rolls both back and is logged, and the
    registration itself never fails here.
    """
    from django.db import transaction
    from django.utils import timezone

    from stapel_core.comm import emit

    from .models import UserSignup

    try:
        consent = resolve_signup_consent(request)
        registered_at = timezone.now().astimezone(datetime.timezone.utc)
        with transaction.atomic():
            _, created = UserSignup.objects.get_or_create(
                user=user,
                defaults={"registered_at": registered_at, "was_guest": bool(was_guest)},
            )
            if not created:
                return
            emit(  # emit-check: ok — the marker row above is this emit's mutation, both inside one savepoint; the swallow below keeps a broker/schema failure from failing registration
                EVENT_USER_SIGNED_UP,
                {
                    "user_id": str(user.pk),
                    "auth_type": getattr(user, "auth_type", None) or "unknown",
                    "registered_at": registered_at.isoformat().replace("+00:00", "Z"),
                    "was_guest": bool(was_guest),
                    "is_staff": bool(getattr(user, "is_staff", False)),
                    "ad_consent": consent.ad_consent,
                    "consent_source": consent.source,
                },
                key=str(user.pk),
                service="auth",
            )
    except Exception:
        logger.exception("Failed to emit %s for user %s", EVENT_USER_SIGNED_UP, user.pk)


__all__ = [
    "AD_CONSENT_VALUES",
    "EVENT_USER_SIGNED_UP",
    "SignupConsent",
    "notify_user_signed_up",
    "resolve_signup_consent",
]
