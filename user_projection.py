"""The user projection — auth announces its identity rows so other services
can hold a shadow copy of a user they have never met.

**The defect this closes.** Every Stapel service that stores its own
``users`` rows fills them from one place: ``JWT_CREATE_USERS_FROM_TOKEN`` in
:mod:`stapel_core.django.jwt.utils`, which materialises a row for the subject
of the token currently being verified. That covers exactly one user per
request — the one holding the token. Any flow that *names* a second user the
service has never seen has nothing to hang a foreign key on: chat's
``participant_ids`` (a buyer opening a thread with a seller who has never
opened chat), an assignee, a recipient, a mentioned account. The insert dies
on a foreign key violation, and the caller gets a bare 500 for a request
that is entirely well-formed.

**The sanctioned shape.** Not "let every service invent a user row when it
needs one" (N silent mirrors, N different truths, and the mirror outlives
the account it copied). The owner of the data publishes the fact, once, and
consumers project it: :data:`~stapel_auth.events.EVENT_USER_CREATED` and
:data:`~stapel_auth.events.EVENT_USER_UPDATED`, emitted here through the
transactional outbox, consumed by the reusable component in
:mod:`stapel_auth.projection`. One owner, one fact stream, one direction.

**One observer, not N call sites** — the same argument
:mod:`stapel_auth.activation` makes for ``user.deactivated``, and it is
stronger here. A user row is born in this module from at least six places
(OTP verify, password register, OAuth resolve, SSO provisioning,
``auth.provision_user``, ``LoginGrantService.exchange``, the anonymous mint,
``POST /admin-users/``) plus every host project's own ``createsuperuser``,
data migration and management shell. A fact stream that a service's foreign
keys depend on cannot be maintained by remembering to call something: it is
attached to the write itself.

**The payload is not designed here.** It is
``serialize_user_to_jwt_data(user)`` verbatim — the very function that builds
the claims a shadow row is otherwise made from. The consumer then applies it
with ``get_or_create_user_from_jwt``, the very function the middleware
applies a token with. Token-driven creation and event-driven creation are
therefore *the same two functions*, not two implementations that agree
today; a field added to one is a field added to both.

Two things this observer deliberately cannot see, both by construction and
both shared with :mod:`stapel_auth.activation`:

* ``QuerySet.update()`` / ``bulk_update()`` bypass model signals. A mass
  ``User.objects.filter(...).update(is_staff=True)`` changes shadow-visible
  state silently. Use :func:`replay` (``manage.py emit_user_projection``)
  afterwards; documented, not papered over.
* A user *deleted* in auth is not announced here. Erasure has its own
  irreversible, GDPR-shaped event (``user.deleted``, stapel-gdpr) with its
  own consumers; conflating "the row changed" with "the person is gone"
  is exactly the mistake #92 spent a module avoiding.

Atomicity: ``post_save`` fires *outside* the transaction ``Model.save()``
opens for itself, so the emit is wrapped in its own ``transaction.atomic()``.
When the caller holds a transaction that block is a savepoint inside it and
the outbox row commits with the user row; in autocommit it is the outermost
atomic, which is what keeps the outbox guarantee honest (and keeps the
``EMIT_OUTSIDE_ATOMIC`` guard quiet on a hot path). Failures are **not**
swallowed: a user row whose creation nobody heard about is the bug this
module exists to close, so the write goes back with the event.
"""

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save, pre_save

from stapel_auth.events import EVENT_USER_CREATED, EVENT_USER_UPDATED

__all__ = [
    "PROJECTED_FIELDS",
    "projection_payload",
    "register_user_projection_observer",
    "replay",
]

#: Model fields whose value can reach a consumer's shadow row. Used for two
#: things: the ``update_fields`` fast path (a save that cannot touch any of
#: them — ``update_last_login``, the hottest write in the module — skips the
#: pre_save SELECT entirely) and the ``.only()`` column list for the stored
#: snapshot. Derived from what ``serialize_user_to_jwt_data`` reads; fields
#: a given ``AUTH_USER_MODEL`` does not define are filtered out at runtime.
PROJECTED_FIELDS = (
    "username",
    "email",
    "phone",
    "auth_type",
    "is_anonymous",
    "is_staff",
    "is_superuser",
    "is_active",
    "staff_roles",
)

#: Instance attribute the pre_save observer parks the stored payload on.
_STORED = "_stapel_auth_projection_stored"

_UNSET = object()


def projection_payload(user) -> dict:
    """The wire payload for *user* — the JWT claim set, verbatim.

    Delegating to ``serialize_user_to_jwt_data`` rather than assembling a
    dict here is the whole design: it is the single definition of "what a
    service is told about a user", shared by the token path and this event
    path, so a shadow row built from either is the same row.
    """
    from stapel_core.django.jwt.utils import serialize_user_to_jwt_data

    return serialize_user_to_jwt_data(user)


def _projected_columns(model) -> list:
    """The subset of :data:`PROJECTED_FIELDS` this user model really stores.

    ``is_anonymous`` is the reason this is computed and not a constant: on a
    stock ``AbstractUser`` it is a *property*, so ``hasattr`` says yes while
    ``.only()`` would raise. Stapel's ``AbstractStapelUser`` shadows it with
    a real column.
    """
    concrete = {f.attname for f in model._meta.concrete_fields}
    return [name for name in PROJECTED_FIELDS if name in concrete]


# ── the observer ────────────────────────────────────────────────────────────


def _remember_projection_state(sender, instance, raw=False, update_fields=None,
                               **kwargs):
    """``pre_save``: park the stored row's payload on the instance.

    Skipped — leaving nothing parked, so ``post_save`` treats the write as
    "no information" and stays quiet — for loaddata, for a first insert (no
    stored row), and for writes whose ``update_fields`` cannot touch any
    projected field.
    """
    if hasattr(instance, _STORED):
        delattr(instance, _STORED)
    if raw or instance.pk is None:
        return
    columns = _projected_columns(sender)
    if update_fields is not None and not (set(update_fields) & set(columns)):
        return
    stored = sender._default_manager.filter(pk=instance.pk).only(*columns).first()
    if stored is None:
        # An insert with a client-generated pk (Stapel users default their
        # UUID): there is no previous state, so there is nothing to diff.
        return
    setattr(instance, _STORED, projection_payload(stored))


def _emit_projection_event(sender, instance, created=False, raw=False, **kwargs):
    """``post_save``: announce a birth, or a real change to a projected field."""
    stored = getattr(instance, _STORED, _UNSET)
    if stored is not _UNSET:
        delattr(instance, _STORED)
    if raw:
        return
    if created:
        _emit(EVENT_USER_CREATED, projection_payload(instance))
        return
    # Nothing parked ⇒ pre_save decided this write cannot have touched a
    # projected field (the update_last_login fast path). Serializing the
    # instance here just to discover that would put the work back on the hot
    # path the fast path exists to keep clear.
    if stored is _UNSET:
        return
    payload = projection_payload(instance)
    if stored == payload:
        return
    _emit(EVENT_USER_UPDATED, payload)


def _emit(event: str, payload: dict) -> None:
    from stapel_core.comm import emit

    # Own atomic block: post_save runs outside the save's transaction, so
    # this is what puts the outbox row in a transaction at all. Nested inside
    # a caller's transaction it is a savepoint and commits with the user row.
    with transaction.atomic():
        emit(event, payload, key=payload["user_id"], service="auth")


def register_user_projection_observer() -> None:
    """Connect the observer to the project's user model (called from
    ``AppConfig.ready``). ``dispatch_uid`` makes it idempotent."""
    pre_save.connect(
        _remember_projection_state,
        sender=settings.AUTH_USER_MODEL,
        dispatch_uid="stapel_auth.user_projection.remember",
    )
    post_save.connect(
        _emit_projection_event,
        sender=settings.AUTH_USER_MODEL,
        dispatch_uid="stapel_auth.user_projection.emit",
    )


# ── backfill ────────────────────────────────────────────────────────────────


def replay(queryset=None, *, batch_size: int = 500) -> int:
    """Re-announce existing users as ``user.created``; returns the count.

    The observer only sees writes that happen after it is installed, so every
    account that existed before this release — and every account changed by a
    ``QuerySet.update()`` since — is invisible to a consumer's shadow table.
    That is not a migration detail: it is the difference between "new users
    can be named in a chat" and "users can be named in a chat". Run it once
    after deploying the consumer, and again after any bulk update.

    ``user.created`` and not ``user.updated`` on purpose: the consumer
    materialises a missing row from either, and a replay is exactly the
    statement "this row exists", which is what a consumer that has never
    heard of the account needs. Applying it to a row that already exists is
    an idempotent no-op field sync.

    Each user is emitted in its own transaction, so a long replay commits
    incrementally rather than holding one transaction over the whole table.
    """
    from django.contrib.auth import get_user_model

    qs = get_user_model()._default_manager.all() if queryset is None else queryset
    count = 0
    for user in qs.iterator(chunk_size=batch_size):
        _emit(EVENT_USER_CREATED, projection_payload(user))
        count += 1
    return count
