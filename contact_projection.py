"""The contact projection — auth announces every deliverable address it holds.

**The defect this closes (D-CONTACT).** A notification service keeps a mirror
of "where can this person be written to" (``stapel_notifications.UserContact``)
and fills it from one event: ``user.contact.changed``. Before this module the
only producer of that event in the whole library was
``AuthenticatorChangeService._apply_change`` — the *change my e-mail/phone*
flow. Every path that **establishes** an address emitted nothing:

* e-mail / phone OTP registration (``otp/views.py`` ``verify_email`` /
  ``verify_phone`` and their registration branches),
* OAuth first login, brand-new account (``otp/views.py``
  ``_resolve_oauth_user`` case 4) — on a Google-first deployment this is
  nearly every account,
* the guest → account upgrade (``_resolve_oauth_user`` case 3, the OTP
  promoters, ``SSOUserService._provision``'s promotion branch),
* SSO provisioning (``sso_service.py`` ``_provision``),
* password registration (``password/views.py``),
* admin-created users (``admin/views.py``),
* login-grant provisioning (``login_grant/services.py``) and
  ``auth.provision_user`` (``functions.py``).

The observable result on a live fleet: a mirror holding only the handful of
accounts that had ever *changed* an address, and transactional mail —
payment receipts, "your summary is ready" — journalled as ``skipped`` with
"no email address for this recipient" for everybody else. The e-mail existed
in auth the whole time.

**Why an observer and not eleven emits.** The list above is the list of
flows that existed on the day this was written. A per-view emit is a rule
that has to be remembered by the author of the *twelfth* login method, and
the failure mode of forgetting is silent: no exception, no failing test,
just mail that is never sent. The fact being announced is not "a view ran",
it is "this row's deliverable address is now X" — a property of the write.
So it is attached to the write, exactly as :mod:`stapel_auth.activation` and
:mod:`stapel_auth.user_projection` attach theirs, and the eleven call sites
need to know nothing.

**Atomicity.** ``post_save`` fires outside the transaction ``Model.save()``
opens for itself, so the emit takes its own ``transaction.atomic()``. Nested
in a caller's transaction that is a savepoint and the outbox row commits with
the user row; in autocommit it is the outermost atomic, which is what makes
the outbox guarantee real. Failures are not swallowed: an address nobody was
told about is the bug this module exists to close.

Two blind spots, both shared with the sibling observers and both stated
rather than papered over:

* ``QuerySet.update()`` / ``bulk_update()`` bypass model signals. A mass
  address rewrite is invisible here. That is one of the two reasons
  ``manage.py notifications_reconcile_contacts`` (stapel-notifications)
  exists — the mirror is repaired by a pull, not by hoping.
* A user *deleted* in auth is not announced here; erasure has its own
  irreversible event (``user.deleted``) with its own consumers.

**Transport.** The canonical emit is ``stapel_core.comm.emit`` through the
transactional outbox, action ``user.contact.changed``. A deployment still
running the pre-comm Kafka consumer (``manage.py consume_contacts``, topic
``stapel.auth.user-contact-changed``) additionally receives a best-effort
publish on that legacy topic, so the mirror keeps filling during the window
where the two services are deployed apart. The legacy publish is
**deprecated** and is the only thing here allowed to fail quietly: the
outbox row is the durable fact.
"""

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save, pre_save

from stapel_auth.events import EVENT_USER_CONTACT_CHANGED

__all__ = [
    "CONTACT_FIELDS",
    "announce_contact",
    "contact_payload",
    "register_contact_projection_observer",
    "replay",
]

#: Model fields whose value can change where a person is reachable. Used for
#: the ``update_fields`` fast path (``update_last_login``, the hottest write
#: in the module, cannot touch any of them and skips the pre_save SELECT) and
#: for the ``.only()`` column list of the stored snapshot.
CONTACT_FIELDS = (
    "email",
    "phone",
    "is_email_verified",
    "is_phone_verified",
)

#: Instance attribute the pre_save observer parks the stored payload on.
_STORED = "_stapel_auth_contact_projection_stored"

_UNSET = object()


def contact_payload(user) -> dict:
    """The wire payload for *user* — addresses plus their verification state.

    ``email``/``phone`` are always present (empty string when unset) so a
    consumer's upsert can CLEAR an address it holds: omitting the key would
    make "this person no longer has a phone" indistinguishable from "this
    event says nothing about phones", and the mirror would keep writing to
    an address the account gave up.

    The verified flags ride along rather than gating the emit. Whether an
    unverified address may be written to is the notification side's policy
    (a passcode to an unverified address is how you verify it; a payment
    receipt to one is not), and a projection that silently withheld the
    facts would leave that policy no input. ``language`` is **not** here:
    auth stores no language field — the recipient's own choice is asked of
    profiles by name (``stapel_notifications.language``), and mirroring a
    guess would give that chain a fourth source of truth.
    """
    return {
        "user_id": str(user.pk),
        "email": (getattr(user, "email", "") or ""),
        "phone": (getattr(user, "phone", "") or ""),
        "email_verified": bool(getattr(user, "is_email_verified", False)),
        "phone_verified": bool(getattr(user, "is_phone_verified", False)),
    }


def _contact_columns(model) -> list:
    """The subset of :data:`CONTACT_FIELDS` this user model really stores.

    A host is free to run an ``AUTH_USER_MODEL`` without ``phone`` or without
    the verified flags; ``.only()`` would raise on a name that is not a
    concrete field.
    """
    concrete = {f.attname for f in model._meta.concrete_fields}
    return [name for name in CONTACT_FIELDS if name in concrete]


def _is_addressable(payload: dict) -> bool:
    """Is there anything here a message could be delivered to?

    An account with neither an e-mail nor a phone — every anonymous guest,
    and a login/password account on a deployment that asks for no address —
    is not announced. This is not an optimisation: an empty mirror row is
    indistinguishable from a real address the consumer has not heard about
    yet, and it is exactly the row that makes
    ``notifications_contacts_missing`` (the sentinel that now watches this
    seam) report health it cannot know.
    """
    return bool(payload["email"] or payload["phone"])


def announce_contact(user) -> bool:
    """Announce *user*'s deliverable address. The choke point.

    Returns True when an event was emitted. Safe to call directly — a
    management command, a data migration, a host that writes addresses
    through ``QuerySet.update()`` — and idempotent from the consumer's point
    of view: the mirror upsert is an update_or_create.
    """
    payload = contact_payload(user)
    if not _is_addressable(payload):
        return False
    _emit(payload)
    return True


def _emit(payload: dict) -> None:
    from stapel_core.comm import emit

    with transaction.atomic():
        emit(
            EVENT_USER_CONTACT_CHANGED,
            payload,
            key=payload["user_id"],
            service="auth",
        )
    _publish_legacy_topic(payload)


def _publish_legacy_topic(payload: dict) -> None:
    """Best-effort mirror onto the pre-comm Kafka topic. DEPRECATED.

    Kept for the deployment window in which a notifications service still
    runs ``manage.py consume_contacts`` (topic
    ``stapel.auth.user-contact-changed``) and not yet the comm action
    consumer. It is deliberately outside the atomic block above and
    deliberately silent on failure: the outbox row emitted a moment ago is
    the durable fact, and a broker hiccup on a deprecated side channel must
    not roll back a user's registration. Remove once no fleet runs that
    consumer.
    """
    try:
        from stapel_core.bus import Event, publish
        from stapel_core.kafka.events import EventType
        from stapel_core.kafka.topics import TOPIC_USER_CONTACT_CHANGED

        publish(
            TOPIC_USER_CONTACT_CHANGED,
            Event(
                event_type=EventType.USER_CONTACT_CHANGED,
                service="auth",
                payload=dict(payload),
                key=payload["user_id"],
            ),
        )
    except Exception:  # pragma: no cover - deprecated side channel
        import logging

        logging.getLogger(__name__).debug(
            "legacy user-contact-changed publish failed for user %s "
            "(the outbox row is the durable fact)", payload["user_id"],
        )


# ── the observer ────────────────────────────────────────────────────────────


def _remember_contact_state(sender, instance, raw=False, update_fields=None,
                            **kwargs):
    """``pre_save``: park the stored row's contact payload on the instance."""
    if hasattr(instance, _STORED):
        delattr(instance, _STORED)
    if raw or instance.pk is None:
        return
    columns = _contact_columns(sender)
    if update_fields is not None and not (set(update_fields) & set(columns)):
        return
    stored = sender._default_manager.filter(pk=instance.pk).only(*columns).first()
    if stored is None:
        # An insert with a client-generated pk (Stapel users default their
        # UUID): no previous state, nothing to diff.
        return
    setattr(instance, _STORED, contact_payload(stored))


def _emit_contact_event(sender, instance, created=False, raw=False, **kwargs):
    """``post_save``: announce a new address, or a real change to one."""
    stored = getattr(instance, _STORED, _UNSET)
    if stored is not _UNSET:
        delattr(instance, _STORED)
    if raw:
        return
    payload = contact_payload(instance)
    if created:
        if _is_addressable(payload):
            _emit(payload)
        return
    if stored is _UNSET:
        # pre_save decided this write cannot have touched a contact field.
        return
    if stored == payload:
        return
    if not _is_addressable(payload) and not _is_addressable(stored):
        # Guest housekeeping: neither before nor after is an address.
        return
    # An account that LOST its last address is announced too — the empty
    # strings are what tell the mirror to stop writing to what it holds.
    _emit(payload)


def register_contact_projection_observer() -> None:
    """Connect the observer to the project's user model (from
    ``AppConfig.ready``). ``dispatch_uid`` makes it idempotent."""
    pre_save.connect(
        _remember_contact_state,
        sender=settings.AUTH_USER_MODEL,
        dispatch_uid="stapel_auth.contact_projection.remember",
    )
    post_save.connect(
        _emit_contact_event,
        sender=settings.AUTH_USER_MODEL,
        dispatch_uid="stapel_auth.contact_projection.emit",
    )


# ── backfill ────────────────────────────────────────────────────────────────


def replay(queryset=None, *, batch_size: int = 500) -> int:
    """Re-announce every addressable account; returns the number emitted.

    The push half of the repair. The pull half —
    ``manage.py notifications_reconcile_contacts`` on the notifications side
    — is the one to prefer for a mirror that is behind, because it reports
    what it changed and does not depend on a consumer keeping up with a
    burst. This exists for the fleet that has no such command in reach, and
    for after a bulk ``QuerySet.update()`` the observer cannot see.
    """
    from django.contrib.auth import get_user_model

    qs = get_user_model()._default_manager.all() if queryset is None else queryset
    count = 0
    for user in qs.iterator(chunk_size=batch_size):
        if announce_contact(user):
            count += 1
    return count
