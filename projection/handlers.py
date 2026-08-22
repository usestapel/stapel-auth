"""Apply the owner's user facts to this service's shadow ``users`` row.

The handler is four lines of routing around one call, and that is the point.
``get_or_create_user_from_jwt`` is the function the JWT middleware already
uses to materialise a shadow row from a token's claims; the event payload is
the same claim set (``serialize_user_to_jwt_data`` on the owner's side), so
the event path and the token path are literally the same writer reached two
ways. Nothing here decides what a shadow user looks like — if it did, the
two would drift the first time a claim was added.

Idempotency comes free from the same place: the function is a get-or-create
that field-syncs an existing row. A redelivered event, a replay of the whole
table, or an event for a user this service already minted from a JWT all end
in the same row with the same values.
"""

import logging

from stapel_core.comm import on_action

from stapel_auth.events import EVENT_USER_CREATED, EVENT_USER_UPDATED

logger = logging.getLogger(__name__)

__all__ = ["apply_user_projection"]


def _is_shadow_store() -> bool:
    """Does this process hold a *copy* of the user table, or the original?

    The same setting the JWT path branches on, deliberately: a service that
    refuses to mint users from a token is the identity owner (or a
    deployment that wants stale references to fail loudly), and it must not
    mint them from an event either. Reusing the switch means the two paths
    cannot disagree about which kind of store this is.
    """
    from django.conf import settings

    return bool(getattr(settings, "JWT_CREATE_USERS_FROM_TOKEN", True))


def apply_user_projection(payload: dict):
    """Upsert the shadow user row described by *payload*. Returns the user.

    Raises when the row could not be materialised, so the caller's transport
    (the outbox relay in-process, the bus consumer across services) applies
    its own retry/DLQ policy instead of silently dropping a user a foreign
    key is about to need.
    """
    from stapel_core.django.jwt.utils import get_or_create_user_from_jwt

    user_id = payload.get("user_id")
    if not user_id:
        raise ValueError("user projection event carries no user_id")
    if not _is_shadow_store():
        logger.debug(
            "user projection %s ignored: JWT_CREATE_USERS_FROM_TOKEN is off, "
            "this service owns its user table", user_id,
        )
        return None

    user = get_or_create_user_from_jwt(payload)
    if user is None:
        raise RuntimeError(f"could not project user {user_id} into the local store")
    return user


@on_action(EVENT_USER_CREATED)
def project_user_created(event) -> None:
    apply_user_projection(event.payload)


@on_action(EVENT_USER_UPDATED)
def project_user_updated(event) -> None:
    # Same handler body as created: the payload is the full claim set, not a
    # delta, so a service that missed the birth still ends up with a correct
    # row rather than an update against nothing.
    apply_user_projection(event.payload)
