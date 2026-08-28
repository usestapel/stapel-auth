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
EVENT_USER_CREATED = "user.created"
EVENT_USER_UPDATED = "user.updated"
EVENT_STAFF_ROLE_ASSIGNED = "staff.role.assigned"
EVENT_STAFF_ROLE_REVOKED = "staff.role.revoked"
EVENT_USER_SESSION_CREATED = "user.session_created"
EVENT_USER_SESSION_REVOKED = "user.session_revoked"
EVENT_USER_MFA_ENABLED = "user.mfa_enabled"
EVENT_USER_MFA_DISABLED = "user.mfa_disabled"
EVENT_USER_DEACTIVATED = "user.deactivated"
EVENT_USER_REACTIVATED = "user.reactivated"
EVENT_USER_MERGED = "user.merged"


@dataclass
class UserRegisteredPayload:
    """Payload for the user.registered event.

    Fields:
        user_id: UUID of the newly created user.
        auth_type: Registration method (email/phone/oauth/password/anonymous/login).
        email: User email if available.
        avatar_url: Avatar URL surfaced by the auth provider (currently only
            populated for OAuth registrations — see ``User.avatar``), None
            otherwise. Dead-reckoning consumers (e.g. profiles) decide what
            to do with it; auth itself never fetches or stores the image.
        language: UI language hint captured at registration (currently only
            populated by login-grant provisioning — workspaces-org-program
            §B3), None otherwise. Same dead-reckoning contract as avatar_url:
            auth stores no language field; consumers (e.g. profiles
            ``app_language``) decide what to do with it.
        display_name: Display-name hint captured at registration (currently
            only populated by ``auth.provision_user`` — workspaces-org-program
            §C1), None otherwise. Same dead-reckoning contract as language:
            consumers (profiles) decide what to do with it; auth mirrors it
            into ``first_name`` and forgets.
    """
    user_id: str
    auth_type: str
    email: str | None = None
    avatar_url: str | None = None
    language: str | None = None
    display_name: str | None = None


@dataclass
class UserProjectionPayload:
    """Payload for ``user.created`` / ``user.updated`` — the user projection
    (schemas/emits/user.created.json, schemas/emits/user.updated.json).

    NOT a second ``user.registered``. ``user.registered`` is a *milestone*
    ("somebody signed up", with dead-reckoning hints like ``avatar_url`` and
    ``display_name`` that auth does not even store); this pair is the
    *identity row itself*, announced so that a service holding a shadow user
    table can materialise a row for a user it has never seen. That is the
    whole reason it exists: before it, a service learned about a user only
    when that user personally presented a JWT (``JWT_CREATE_USERS_FROM_TOKEN``
    in ``stapel_core.django.jwt.utils``), so any flow naming a SECOND user —
    chat's ``participant_ids``, an assignee, a recipient — hit a bare foreign
    key violation.

    **The field set is not chosen here.** It is exactly
    ``stapel_core.django.jwt.utils.serialize_user_to_jwt_data(user)`` — the
    same function that builds the JWT claims a shadow row is otherwise made
    from. Mirroring that call rather than re-listing its fields is what makes
    the two writers (token-driven creation, event-driven creation) incapable
    of drifting: they read the same serializer and are applied by the same
    materializer. Adding a field here means adding a claim there, on purpose.

    Fields (all optional ones are OMITTED, not nulled, when the user model
    has no such field or the value is empty — mirroring the serializer):
        user_id: UUID of the user (always present; the projection key).
        username: ``USERNAME_FIELD`` value.
        email: Email address, or None.
        phone: E.164 phone, omitted when unset.
        auth_type: How the account was born (email/phone/oauth/sso/
            anonymous/login), omitted on user models without the field.
        is_anonymous: Guest account flag, omitted likewise.
        is_staff / is_superuser / is_active: Django's three account flags.
        staff_roles: Materialised role names — present only for staff or
            superuser accounts, exactly as in the JWT claim (present-but-
            empty is authoritative "zero roles"; absence carries no
            information and consumers must not act on it).
    """
    user_id: str
    username: str = ""
    email: str | None = None
    phone: str | None = None
    auth_type: str | None = None
    is_anonymous: bool | None = None
    is_staff: bool = False
    is_superuser: bool = False
    is_active: bool = True
    staff_roles: list | None = None


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


@dataclass
class UserMfaEnabledPayload:
    """Payload for the user.mfa_enabled event
    (schemas/emits/user.mfa_enabled.json — workspaces-org-program §C3).

    ACCOUNT-LEVEL transition, not a per-factor tick: emitted when the user
    goes from "no strong second factor" to "has one" (strength canon: totp/
    passkey/otp_phone are strong, a bare email code is not — see
    ``stapel_core.verification.strong_factors``). Consumers (workspaces
    require_mfa suspension) may act on it directly without re-querying
    ``auth.mfa_status``. Activating a SECOND strong factor emits nothing —
    the account state did not change.

    Fields:
        user_id: UUID of the user.
        factor: Registry id of the factor whose activation caused the
            transition ("totp" | "passkey").
    """
    user_id: str
    factor: str


@dataclass
class UserMfaDisabledPayload:
    """Payload for the user.mfa_disabled event (mirror of enabled).

    Emitted when the user loses their LAST strong factor (account-level
    transition — removing one passkey of two, or disabling TOTP while a
    verified phone still counts as strong, emits nothing). Emission points:
    TOTP disable/force-disable (incl. the delayed-change execute task) and
    passkey deactivation.
    """
    user_id: str
    factor: str


@dataclass
class UserDeactivatedPayload:
    """Payload for the user.deactivated event
    (schemas/emits/user.deactivated.json — #92).

    ADMINISTRATIVE access removal, emphatically **not** a GDPR erasure. The
    account row, its factors and its history all stay; ``is_active`` flips
    to False and the account stops being admitted anywhere. Consumers must
    treat it as *reversible* and keep the user's records: the mirror event
    ``user.reactivated`` puts everything back. The irreversible signal is
    ``user.deleted`` (gdpr), which is a different event with a different
    consumer and must never be conflated with this one.

    Emitted once per real ``True -> False`` transition of ``is_active``, from
    the single observer in :mod:`stapel_auth.activation` — so an admin
    checkbox, a management shell, and ``deactivate_user()`` all produce
    exactly one event, and re-saving an already-deactivated user produces
    none.

    Fields:
        user_id: UUID of the deactivated user.
        reason: Free-text/enum reason recorded by the caller of
            ``deactivate_user`` (open vocabulary), omitted when unknown —
            an admin checkbox carries no reason.
        actor_id: UUID of the staff user who performed it, omitted for
            programmatic/unknown actors.
    """
    user_id: str
    reason: str | None = None
    actor_id: str | None = None


@dataclass
class UserReactivatedPayload:
    """Payload for the user.reactivated event — mirror of deactivated.

    Emitted on the ``False -> True`` transition. Its existence is what makes
    deactivation safe to act on destructively-looking ways downstream: a
    consumer that suspends memberships on ``user.deactivated`` MUST lift
    them here, or a restored account logs in to an empty product ("logged
    in, sees nothing").
    """
    user_id: str
    actor_id: str | None = None


@dataclass
class UserMergedPayload:
    """Payload for the user.merged event (schemas/emits/user.merged.json).

    Two accounts became one: ``from_user_id`` no longer exists, and every
    record that pointed at it now belongs to ``into_user_id``. Auth emits it
    when a guest verifies an authenticator that an existing account already
    holds — the guest row is deleted, the existing account survives.

    **What a consumer MUST do.** Reassign every row your module owns from
    ``from_user_id`` to ``into_user_id`` — a bare ``filter(user_id=from).
    update(user_id=into)`` for each table, plus whatever de-duplication your
    own uniqueness constraints demand (the same listing favourited by both
    accounts, both accounts in one conversation). Doing nothing is not a
    no-op: your foreign keys are ``on_delete=CASCADE``, so the rows are gone
    the moment auth commits, and the user watches their saved listings and
    their chat history disappear at sign-in.

    Two properties shape how that work must be written:

    - Delivery is **at-least-once** (outbox relay retries), so the reassign
      must be idempotent — a second delivery of the same merge has to be a
      no-op, not a second migration or a constraint violation.
    - ``from_user_id`` is **already gone** from auth's user table by the time
      this is read. Do not resolve it against auth, and do not treat its
      absence as a reason to skip: the id is a key for rows you still hold,
      nothing more. ``into_user_id`` is the account that exists, and its own
      projection event (``user.created`` / ``user.updated``) precedes this
      one, so a shadow user table has a row to reassign onto.

    Fields:
        from_user_id: UUID of the account that ceased to exist (the guest).
        into_user_id: UUID of the surviving account.
        reason: Why the merge happened. ``"anonymous_promotion"`` — a guest
            signed in as an account that already existed — is the only
            reason auth emits today; the field exists so a consumer can tell
            it apart from a future admin-initiated merge without guessing.
    """
    from_user_id: str
    into_user_id: str
    reason: str = "anonymous_promotion"


# Canonical event registry — keyed by the action name actually emitted.
EVENT_REGISTRY = {
    EVENT_USER_REGISTERED: UserRegisteredPayload,
    EVENT_USER_CREATED: UserProjectionPayload,
    EVENT_USER_UPDATED: UserProjectionPayload,
    EVENT_STAFF_ROLE_ASSIGNED: StaffRoleAssignedPayload,
    EVENT_STAFF_ROLE_REVOKED: StaffRoleRevokedPayload,
    EVENT_USER_SESSION_CREATED: UserSessionCreatedPayload,
    EVENT_USER_SESSION_REVOKED: UserSessionRevokedPayload,
    EVENT_USER_MFA_ENABLED: UserMfaEnabledPayload,
    EVENT_USER_MFA_DISABLED: UserMfaDisabledPayload,
    EVENT_USER_DEACTIVATED: UserDeactivatedPayload,
    EVENT_USER_REACTIVATED: UserReactivatedPayload,
    EVENT_USER_MERGED: UserMergedPayload,
}
