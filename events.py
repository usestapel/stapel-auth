"""Events published by stapel-auth.

Delivery goes through ``stapel_core.comm.emit`` (transactional outbox;
in-process in a monolith, bus in microservices). On the bus transport the
topic is the action name — ``user.registered`` — so that is the canonical
constant. The old Kafka topic ``stapel.auth.user-registered`` is retired:
auth emits ``emit("user.registered")`` and consumers (e.g. workspaces'
``consume_auth_events``) subscribe to ``user.registered``.
"""
from dataclasses import dataclass

EVENT_USER_REGISTERED = "user.registered"

# Back-compat alias for any importer still referencing the old name.
TOPIC_USER_REGISTERED = EVENT_USER_REGISTERED


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


# Canonical event registry — keyed by the action name actually emitted.
EVENT_REGISTRY = {
    EVENT_USER_REGISTERED: UserRegisteredPayload,
}
