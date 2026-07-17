"""Events published by stapel-auth.

Delivery goes through ``stapel_core.comm.emit`` (transactional outbox;
in-process in a monolith, bus in microservices). On the bus transport the
topic is the action name — ``user.registered`` — so that is the canonical
constant. The old Kafka topic ``stapel.auth.user-registered`` is retired:
auth emits ``emit("user.registered")`` and consumers (e.g. workspaces'
``consume_auth_events``) subscribe to ``user.registered``.
"""
from dataclasses import dataclass, field

EVENT_USER_REGISTERED = "user.registered"
EVENT_STAFF_ROLE_ASSIGNED = "staff.role.assigned"
EVENT_STAFF_ROLE_REVOKED = "staff.role.revoked"
EVENT_USER_SESSION_CREATED = "user.session_created"
EVENT_USER_SESSION_REVOKED = "user.session_revoked"


@dataclass
class UserRegisteredPayload:
    """Payload for the user.registered event.

    Fields:
        user_id: UUID of the newly created user.
        auth_type: Registration method (email/phone/oauth/password/anonymous).
        email: User email if available.
        avatar_url: Avatar URL surfaced by the auth provider (currently only
            populated for OAuth registrations — see ``User.avatar``), None
            otherwise. Dead-reckoning consumers (e.g. profiles) decide what
            to do with it; auth itself never fetches or stores the image.
    """
    user_id: str
    auth_type: str
    email: str | None = None
    avatar_url: str | None = None


@dataclass
class StaffRoleAssignedPayload:
    """Payload for the staff.role.assigned event (admin-suite AS-2, §3.8).

    Fields:
        user_id: UUID of the user the role was assigned to.
        role: Role name (a key of the STAPEL_ACCESS["ROLES"] registry).
        staff_roles: The user's complete role list AFTER the change —
            self-contained audit record for the eventstore stream (S6).
        actor_id: UUID of the staff user who performed the assignment,
            None for programmatic/management assignments.
    """
    user_id: str
    role: str
    staff_roles: list = field(default_factory=list)
    actor_id: str | None = None


@dataclass
class StaffRoleRevokedPayload:
    """Payload for the staff.role.revoked event (mirror of assigned)."""
    user_id: str
    role: str
    staff_roles: list = field(default_factory=list)
    actor_id: str | None = None


@dataclass
class UserSessionCreatedPayload:
    """Payload for the user.session_created event
    (schemas/emits/user.session_created.json).

    Fields:
        user_id: UUID of the authenticated user.
        session_id: UUID of the UserSession row.
        device_type: Parsed device class (desktop/mobile/tablet/unknown).
        created_at: ISO-8601 creation instant of the session.
        ip_address: Client IP when known; omitted from the wire payload when
            None (the schema field is a plain string, not nullable).
    """
    user_id: str
    session_id: str
    device_type: str
    created_at: str
    ip_address: str | None = None


@dataclass
class UserSessionRevokedPayload:
    """Payload for the user.session_revoked event
    (schemas/emits/user.session_revoked.json) — logout, per-session revoke,
    revoke-all, or an admin/security action."""
    user_id: str
    session_id: str


# Canonical event registry — keyed by the action name actually emitted.
EVENT_REGISTRY = {
    EVENT_USER_REGISTERED: UserRegisteredPayload,
    EVENT_STAFF_ROLE_ASSIGNED: StaffRoleAssignedPayload,
    EVENT_STAFF_ROLE_REVOKED: StaffRoleRevokedPayload,
    EVENT_USER_SESSION_CREATED: UserSessionCreatedPayload,
    EVENT_USER_SESSION_REVOKED: UserSessionRevokedPayload,
}
