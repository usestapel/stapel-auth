"""Account activation state — the administrative deactivate/reactivate seam (#92).

Why this module exists. ``is_active=False`` used to be a *local* fact: since
0.15.0 :mod:`stapel_auth.sessions.guard` refuses a session to a deactivated
account on all 19 issuance paths, and that was the end of it. Nothing
downstream ever learned about the flip, so a deactivated user kept every
workspace membership, kept counting against the owner's seat bill, and kept
appearing in every member list — "deactivation propagates nowhere but
login". This module is the missing announcement.

**Three states, kept apart on purpose** (the distinction is the whole point
of #92):

``active``
    ``is_active=True``. :func:`stapel_auth.sessions.guard.account_disabled_error`
    returns ``None`` — the account is admitted.
``suspended``
    ``is_active=False`` — administrative, **reversible** access removal.
    Every row the account owns stays exactly where it is. Downstream
    consumers must *suspend*, never delete. Announced as
    ``user.deactivated``, undone by ``user.reactivated``.
``deleted``
    GDPR erasure — a different mechanism entirely
    (:class:`stapel_auth.gdpr.AuthGDPRProvider`, announced by the gdpr
    module's ``user.deleted``). Irreversible, row-destroying, and **not**
    reachable from this module: nothing here ever emits ``user.deleted`` and
    nothing here deletes anything. Conflating the two would turn "the admin
    unticked a box" into "the account is gone".

**One observer, not one call site.** The events are emitted by the
``pre_save``/``post_save`` pair below, watching the real ``is_active``
transition on the user row, rather than by :func:`deactivate_user` alone.
``is_active`` is a plain Django field with a checkbox in every admin: a
service function would have been bypassed by the admin, by
``createsuperuser --no-input`` follow-ups, by a management shell, and by
every host project that flips the flag itself. Watching the field means all
of them announce, and it is what makes the events *idempotent at the
source*: re-saving an already-deactivated user is not a transition and emits
nothing.

Two things the observer deliberately cannot see, both by construction:

* ``QuerySet.update()`` (and ``bulk_update``) bypass model signals — a mass
  ``User.objects.filter(...).update(is_active=False)`` deactivates silently.
  Use :func:`deactivate_user` for that; documented, not papered over.
* ``reason`` / ``actor`` are not fields, so a bare ``user.is_active = False;
  user.save()`` carries neither. :func:`deactivate_user` stashes them on the
  instance for the observer to pick up; the flag-flip path emits the event
  without them, which is exactly what the schema's optional fields mean.

Atomicity: ``post_save`` fires *outside* the transaction ``Model.save()``
opens for itself, so the emit is atomic with the write only when the caller
holds a transaction. :func:`deactivate_user`/:func:`reactivate_user` open
one; the Django admin change-form already runs inside one. A bare
``user.save()`` in a shell emits in autocommit — allowed (stapel-core's
``EMIT_OUTSIDE_ATOMIC`` default is ``warn``), and the reason the service
functions exist.
"""

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save, pre_save

from stapel_auth.events import EVENT_USER_DEACTIVATED, EVENT_USER_REACTIVATED

__all__ = [
    "STATE_ACTIVE",
    "STATE_DELETED",
    "STATE_SUSPENDED",
    "account_state",
    "deactivate_user",
    "is_deactivated",
    "reactivate_user",
    "register_activation_observer",
]

#: The account is admitted (``is_active=True``).
STATE_ACTIVE = "active"
#: Administratively deactivated — reversible, nothing destroyed.
STATE_SUSPENDED = "suspended"
#: GDPR-erased. Never produced by this module; it exists in the vocabulary so
#: that "suspended" and "deleted" can never be spelled the same way.
STATE_DELETED = "deleted"

#: Instance attribute the pre_save observer parks the previous value on.
_WAS_ACTIVE = "_stapel_auth_was_active"
#: Instance attributes :func:`deactivate_user` uses to hand the observer the
#: context a bare field flip cannot carry.
_PENDING_REASON = "_stapel_auth_deactivation_reason"
_PENDING_ACTOR = "_stapel_auth_deactivation_actor"

_UNSET = object()


def is_deactivated(user) -> bool:
    """Is *user* refused admission because the account is deactivated?

    Delegates to :func:`stapel_auth.sessions.guard.account_disabled_error`,
    the predicate the 19 issuance paths already gate on, instead of
    re-reading ``is_active`` here. One definition of "disabled", so this
    module and the session guard can never drift apart on what it means.
    """
    from stapel_auth.sessions.guard import account_disabled_error

    return account_disabled_error(user) is not None


def account_state(user) -> str:
    """:data:`STATE_ACTIVE` or :data:`STATE_SUSPENDED` for a live user row.

    :data:`STATE_DELETED` is deliberately unreachable here: a GDPR-erased
    account has no row to ask.
    """
    return STATE_SUSPENDED if is_deactivated(user) else STATE_ACTIVE


def deactivate_user(user, *, reason: str | None = None, actor=None) -> bool:
    """Administratively deactivate *user*. Returns True on a real transition.

    Reversible by :func:`reactivate_user`; nothing is deleted, here or
    downstream. An already-deactivated user is a no-op returning False with
    no event — the caller may retry freely.

    ``reason`` (open vocabulary) and ``actor`` (the staff user who did it)
    ride on the ``user.deactivated`` payload; both are optional because the
    admin checkbox path has neither.
    """
    if is_deactivated(user):
        return False
    setattr(user, _PENDING_REASON, reason)
    setattr(user, _PENDING_ACTOR, actor)
    try:
        with transaction.atomic():
            user.is_active = False
            user.save(update_fields=["is_active"])
    finally:
        for attr in (_PENDING_REASON, _PENDING_ACTOR):
            if hasattr(user, attr):
                delattr(user, attr)
    return True


def reactivate_user(user, *, actor=None) -> bool:
    """Restore access for a deactivated *user*. Returns True on a transition.

    The mirror of :func:`deactivate_user`, and not optional: a consumer that
    suspends memberships on ``user.deactivated`` lifts them on
    ``user.reactivated``. Without this event a restored account logs in to
    an empty product.
    """
    if not is_deactivated(user):
        return False
    setattr(user, _PENDING_ACTOR, actor)
    try:
        with transaction.atomic():
            user.is_active = True
            user.save(update_fields=["is_active"])
    finally:
        if hasattr(user, _PENDING_ACTOR):
            delattr(user, _PENDING_ACTOR)
    return True


# ── the observer ────────────────────────────────────────────────────────────


def _remember_activation_state(sender, instance, raw=False, update_fields=None,
                               **kwargs):
    """``pre_save``: park the stored ``is_active`` on the instance.

    Skipped (leaving no parked value, so ``post_save`` stays quiet) for
    loaddata, for inserts, and for writes whose ``update_fields`` cannot
    touch ``is_active`` — the last case is what keeps the extra SELECT off
    the hot login path (``update_last_login`` saves ``update_fields=
    ["last_login"]``).
    """
    if hasattr(instance, _WAS_ACTIVE):
        delattr(instance, _WAS_ACTIVE)
    if raw or instance.pk is None:
        return
    if update_fields is not None and "is_active" not in set(update_fields):
        return
    # None ⇒ no stored row (an insert with a client-generated pk): no
    # previous state, therefore no transition to announce.
    was = (
        sender._default_manager.filter(pk=instance.pk)
        .values_list("is_active", flat=True)
        .first()
    )
    if was is None:
        return
    setattr(instance, _WAS_ACTIVE, bool(was))


def _emit_activation_transition(sender, instance, created=False, raw=False,
                                **kwargs):
    """``post_save``: emit iff ``is_active`` actually flipped."""
    was = getattr(instance, _WAS_ACTIVE, _UNSET)
    if was is not _UNSET:
        delattr(instance, _WAS_ACTIVE)
    if raw or created or was is _UNSET:
        return
    now = bool(instance.is_active)
    if was == now:
        return

    from stapel_core.comm import emit

    payload = {"user_id": str(instance.pk)}
    actor = getattr(instance, _PENDING_ACTOR, None)
    if actor is not None:
        payload["actor_id"] = str(getattr(actor, "pk", actor))
    if now:
        event = EVENT_USER_REACTIVATED
    else:
        event = EVENT_USER_DEACTIVATED
        reason = getattr(instance, _PENDING_REASON, None)
        if reason is not None:
            payload["reason"] = str(reason)
    emit(  # emit-check: ok — post_save receiver; deactivate_user/reactivate_user and the admin change-form hold the atomic that performs the is_active write
        event,
        payload,
        key=str(instance.pk),
        service="auth",
    )


def register_activation_observer() -> None:
    """Connect the observer to the project's user model (called from
    ``AppConfig.ready``). ``dispatch_uid`` makes it idempotent."""
    pre_save.connect(
        _remember_activation_state,
        sender=settings.AUTH_USER_MODEL,
        dispatch_uid="stapel_auth.activation.remember",
    )
    post_save.connect(
        _emit_activation_transition,
        sender=settings.AUTH_USER_MODEL,
        dispatch_uid="stapel_auth.activation.emit",
    )
