"""What stapel-auth erases when a subject is erased — one operation, two callers.

Auth was the last module in the fleet with no ``gdpr.owner.probe`` handler:
it *was* a declared data owner, its provider *did* run in a monolith, and
the owners-health board still reported ``auth: alive=false`` forever,
because liveness is answered by the erasure subscriber and auth had none.
A probe answered from anywhere else would have proved only that a container
is running.

So the operation lives here once and is reached two ways:

* :class:`~stapel_auth.gdpr.AuthGDPRProvider` — the in-process registry the
  orchestrator walks in a monolith (``provider.delete(user_id)``);
* the ``gdpr.erasure.requested`` / ``user.deleted`` subscribers that
  :func:`stapel_core.gdpr.register_gdpr_owner` builds from this callable in
  ``apps.ready()`` — the path that also answers the probe.

**Auth is the module that hosts stapel-gdpr**, so in the fleet's own
deployment BOTH paths run in one process for one account erasure. That is
by design and it does not double-receipt: the orchestrator's local receipt
(``_record_local_receipts``) skips a part that is already ``done``, and
``mark_section_erased`` excludes ``done`` parts from its update, so
whichever path arrives second finds the receipt already written and changes
nothing. The erasure itself runs twice and reports the ``0`` rows the second
run touched — which is what an idempotent erasure looks like, and the same
thing that happens on a broker redelivery.

``erase_subject`` deletes; it does not anonymize. Nothing here is the
product's record: sessions, devices, passkeys, login attempts, audit rows,
linked provider accounts and staff roles are the person's own trail, and a
trail nobody can attribute is not worth keeping. The one thing that
survives an erasure is deliberately not a row of this module's: the
re-registration hashes (irreversible SHA-256 of email/phone, 24-month
retention) are written **before** the identifiers are destroyed, because
they are what lets a deployment recognise the same person coming back
without keeping anything that names them.
"""
from __future__ import annotations

#: The name this module answers to in ``STAPEL_GDPR["DATA_OWNERS"]`` — the
#: same string as ``AuthGDPRProvider.section``, because an owner with two
#: names is an owner whose receipts land on nobody's part.
OWNER = 'auth'

#: Subject types this module can really erase, and therefore the only ones
#: it claims and answers ``gdpr.owner.alive`` with. Everything auth stores
#: hangs off exactly one id — the user's — so a workspace or meeting
#: erasure has no key to match on here; claiming the type would mint a
#: receipt for work nobody could have done.
SUBJECT_TYPES = ('account',)

#: How long a re-registration hash is kept (24 months).
REREGISTRATION_RETENTION_DAYS = 730


def erase_subject(subject_type: str, subject_key, workspace_id=None) -> dict | None:
    """Erase one subject's authentication trail. Returns the receipt's counts.

    ``None`` means "this key names nothing of mine" — the subject type is
    not one this module claims, so the caller owes no receipt (stapel-gdpr
    creates a part only for owners that claim the type).

    Idempotent: every row is deleted by user id, so a redelivery matches
    nothing and receipts its zeroes rather than pretending the work
    happened twice. ``workspace_id`` is accepted and ignored — an account
    request may carry it as a partition hint for owners that need one, and
    narrowing by it here would leave the subject's credentials in every
    other tenant.

    A key this module cannot parse raises ``ValueError`` /
    ``ValidationError`` out of the ORM, which the protocol handler logs and
    never receipts: an unusable key names no row here, and a receipt would
    claim an erasure that did not happen.
    """
    if subject_type not in SUBJECT_TYPES:
        return None
    # Never stringified: the user pk is a UUID in the fleet's own deployment
    # and an integer in others, and both spellings must reach the ORM as they
    # came — the protocol hands over a string, the in-process provider hands
    # over whatever the host's pk is, and a str() around the latter turns a
    # valid integer key into an unparseable one.
    key = subject_key.strip() if isinstance(subject_key, str) else subject_key
    if key is None or key == '':
        return None

    from django.contrib.auth import get_user_model

    from stapel_auth.otp.services import email_code_store, phone_code_store

    from .models import (
        AuthAuditLog, AuthenticatorChangeRequest, LinkedOAuthAccount,
        LoginAttempt, OrgMembership, PasskeyCredential, RefreshTokenTracker,
        SignupAttribution, StaffRoleAssignment, TOTPDevice, UserSession,
        VerificationPreference,
    )

    # Before anything is destroyed: the identifiers the login-attempt rows
    # are keyed on, and the hashes that outlive the account.
    user = get_user_model().objects.filter(pk=key).first()
    email = (user.email or '') if user is not None else ''
    phone = str(getattr(user, 'phone', '') or '') if user is not None else ''
    identifiers = [value for value in (email, phone) if value]
    store_reregistration_hashes(key)
    # Pending codes expire on their own, but an erasure must not wait ten
    # minutes to be true.
    if email:
        email_code_store.discard(email)
    if phone:
        phone_code_store.discard(phone)

    counts = {
        'refresh_tokens':          _deleted(RefreshTokenTracker, user_id=key),
        'sessions':                _deleted(UserSession, user_id=key),
        'totp_devices':            _deleted(TOTPDevice, user_id=key),
        'passkeys':                _deleted(PasskeyCredential, user_id=key),
        'authenticator_changes':   _deleted(AuthenticatorChangeRequest, user_id=key),
        'login_attempts': (
            _deleted(LoginAttempt, identifier__in=identifiers) if identifiers else 0
        ),
        'audit_log':               _deleted(AuthAuditLog, user_id=key),
        'sso_memberships':         _deleted(OrgMembership, user_id=key),
        # Not touched before 0.25.0, and the reason a receipt for this owner
        # would have been a lie: the linked provider accounts are the
        # person's Google/GitHub ids (plus the email and display name those
        # providers reported), the staff roles name them by FK, and the
        # step-up preferences are theirs. The default primary-identity
        # strategy is `anonymize`, which keeps the user row — so nothing
        # cascaded them away either.
        'oauth_links':             _deleted(LinkedOAuthAccount, user_id=key),
        'staff_roles':             _deleted(StaffRoleAssignment, user_id=key),
        'verification_preferences': _deleted(VerificationPreference, user_id=key),
        # The advertising click the account was born from. A CASCADE would
        # take it only if the user ROW went away, and the default
        # primary-identity strategy is `anonymize` — the row stays. An
        # erasure that left this behind would keep the one identifier that
        # ties the person to the ad they clicked.
        'signup_attribution':      _deleted(SignupAttribution, user_id=key),
    }
    return counts


def user_identifiers(user_id) -> list[str]:
    """The email/phone a subject's login attempts are keyed on.

    Read before the erasure, because ``LoginAttempt`` rows carry the
    identifier that was typed and no user id at all — the whole point of a
    table that must record attempts by people who never signed in.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.filter(pk=user_id).first()
    if user is None:
        return []
    ids = []
    if user.email:
        ids.append(user.email)
    if getattr(user, 'phone', None):
        ids.append(str(user.phone))
    return ids


def store_reregistration_hashes(user_id) -> None:
    """Store irreversible hashes for re-registration detection (24 months).

    The hash model is resolved lazily from the ``REREGISTRATION_MODEL`` auth
    setting (default: ``stapel_gdpr.models.ReRegistrationHash``) so
    stapel-auth has no import-time dependency on stapel-gdpr. If the model
    is unavailable we degrade to a warning: a deployment without the hash
    store must still be able to erase.
    """
    import warnings

    from django.contrib.auth import get_user_model
    from django.utils.module_loading import import_string

    from .conf import auth_settings

    model_path = auth_settings.REREGISTRATION_MODEL
    if not model_path:
        return
    try:
        # Resolved as an AVAILABILITY probe, not for use: the row is written
        # by the owning library's store_hashes() below, which knows the hash
        # format. What this still answers is "is the configured model even
        # installed" — a deployment without it must be able to erase.
        import_string(model_path)
    except ImportError:
        warnings.warn(
            f"stapel-auth: re-registration model {model_path!r} is not "
            "available — skipping re-registration hash storage. Install "
            "stapel-gdpr or point STAPEL_AUTH['REREGISTRATION_MODEL'] at "
            "a compatible model.",
            stacklevel=2,
        )
        return

    User = get_user_model()
    user = User.objects.filter(pk=user_id).first()
    if user is None:
        return

    # The hash FORMAT belongs to the library that owns the model, and this
    # module used to compute its own: a bare `sha256(email.lower().strip())`,
    # with no key, no salt and no purpose binding — recoverable from a
    # wordlist in seconds — and it named no scheme, so the model's
    # `unverified` default spoke for it.
    #
    # Both halves of that were live defects. The digest leaked the address it
    # was supposed to protect, and the unnamed scheme made the row one the
    # owning library reports through an ERROR-level system check, which means
    # the identity service refuses to boot once such a row exists. Measured on
    # 2026-09-16, by a deliberate erasure drill: the erasure wrote one correct
    # hmac-sha256-v1 row (from the owning library) and two unverified ones
    # (from here) in the same second, and auth crash-looped on its next
    # restart, hours later, on `gdpr.E004`.
    #
    # So this delegates. `store_hashes` computes the purpose-bound keyed HMAC,
    # records the scheme, sets the retention, and is idempotent — everything
    # below used to approximate, wrongly.
    try:
        from stapel_gdpr.reregistration import store_hashes
    except ImportError:
        store_hashes = None

    if store_hashes is not None:
        store_hashes(
            user.pk,
            email=user.email or None,
            phone=str(user.phone) if getattr(user, 'phone', None) else None,
        )
        return

    # A deployment that pointed REREGISTRATION_MODEL at its own model without
    # the owning library. We cannot compute that model's hash format, and
    # guessing is what produced the defect above, so we do not write: a
    # missing re-registration record costs a deletion-oracle check, while a
    # wrong one costs the address and the service's next boot.
    warnings.warn(
        "stapel-auth: re-registration hashes NOT stored — "
        f"{model_path!r} is configured but stapel_gdpr.reregistration is not "
        "importable, and this module will not invent a hash format. Install "
        "stapel-gdpr, or have your model's library expose a store_hashes().",
        stacklevel=2,
    )


def _deleted(model, **lookup) -> int:
    """Rows of *model* this run actually removed — what a receipt may claim.

    Django's ``delete()`` returns the total across cascades; the per-label
    breakdown beside it is the honest number for this model, so a count
    never inflates itself with somebody else's rows.
    """
    _, per_model = model.objects.filter(**lookup).delete()
    return per_model.get(model._meta.label, 0)


__all__ = ['OWNER', 'SUBJECT_TYPES', 'erase_subject', 'store_reregistration_hashes',
           'user_identifiers']
