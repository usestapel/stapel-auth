"""Kafka events published by stapel-auth."""
from dataclasses import dataclass

TOPIC_USER_REGISTERED = "stapel.auth.user-registered"


@dataclass
class UserRegisteredPayload:
    """Payload for the user.registered event.

    Fields:
        user_id: UUID of the newly created user.
        auth_type: Registration method (email/phone/oauth/password/anonymous).
        email: User email if available.
    """
    user_id: str
    auth_type: str
    email: str | None = None


# Canonical event registry — used by iron_event_lint.py to verify
# producer/consumer schema consistency.
EVENT_REGISTRY = {
    TOPIC_USER_REGISTERED: UserRegisteredPayload,
}
