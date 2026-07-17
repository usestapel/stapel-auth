"""Staff role transport — assignments, JWT claim, audit events (admin-suite AS-2).

Role *definitions* (name → clearance profile) are deploy config, owned by
``stapel_core.access`` (AS-1: ``STAPEL_ACCESS["ROLES"]`` merge-registry).
This module owns role *assignments* (user → role names) and their transport:

- :func:`assign_staff_role` / :func:`revoke_staff_role` — the ONLY write
  paths (invariant A2: auth is the single writer; consumer services are
  read-only recipients of the claim). Both emit outbox events
  (``staff.role.assigned`` / ``staff.role.revoked``) in the same transaction
  as the row change — assignment and audit record commit together.
- :func:`serialize_user_to_jwt_data` — core JWT payload plus the
  ``staff_roles`` claim. The claim is present for every staff/superuser
  token, **even when the list is empty**: an empty list is authoritative
  ("this user holds zero roles") and is what lets a revocation propagate to
  consumer services under the sync-down REPLACE semantics (в.3). Absence of
  the claim (tokens minted before AS-2) means "no information" — consumers
  must not touch their local copy for such tokens.
- :func:`assignment_roles` — a ``STAPEL_ACCESS["ROLE_SOURCES"]`` source for
  the auth service itself: the mandate reads roles straight from the
  assignment table, so an in-flight revocation takes effect on the very next
  request without waiting for a token refresh. Configure on the auth service:

      STAPEL_ACCESS = {
          "ROLE_SOURCES": [
              "stapel_auth.staff_roles.assignment_roles",
              "stapel_core.access.sources.claim_roles",
              "stapel_core.access.sources.group_roles",
          ],
      }

Downgrade/upgrade safety of the claim (see MODULE.md "Staff roles"):
old tokens without the claim can neither add nor remove roles at consumers;
old tokens *with* the claim can resurrect since-revoked roles only until
their own ``exp`` (access-token TTL — invariant A3); immediate revocation is
the existing Redis user-blacklist.
"""
from __future__ import annotations

import logging

from django.db import transaction

logger = logging.getLogger(__name__)

#: Soft guard for claim bloat: a staff_roles claim longer than this (joined
#: length in characters) is still emitted but logged — role sets are meant to
#: be a handful of short registry names, not a permission dump.
CLAIM_SIZE_WARN_CHARS = 512


class UnknownStaffRoleError(ValueError):
    """Role name is not defined in the STAPEL_ACCESS["ROLES"] registry."""


class StaffRoleTargetNotStaffError(ValueError):
    """Assignment target is not staff — roles would be dormant privileges.

    Refusing the write (instead of storing a no-op row) prevents the quiet
    privilege-combination hazard: a role parked on a non-staff account would
    silently activate the day someone flips ``is_staff`` for an unrelated
    reason.
    """


def _is_unsaved(user) -> bool:
    """True for None / anonymous / not-yet-persisted users.

    ``pk is None`` alone is not enough: the stapel user model has a UUID
    primary key with a default, so an unsaved instance already carries a pk
    (same guard as ``stapel_core.access.sources.group_roles``).
    """
    if user is None or user.pk is None:
        return True
    return getattr(getattr(user, "_state", None), "adding", True)


def _registry_roles() -> dict:
    from stapel_core.access import effective_roles

    return effective_roles()


def _materialize_field(user) -> None:
    """Mirror the assignment table into the user's ``staff_roles`` field.

    The field (AbstractStapelUser, stapel-core AS-2 counterpart) is what
    core-side token paths — ``load_user_by_uid`` and the middleware's
    proactive refresh — serialize from. Keeping it in sync inside the same
    transaction as the assignment write means those paths can never mint a
    token with stale roles. No-op on a user model without the field (older
    stapel-core), because the assignment table stays the source of truth on
    the auth service either way.
    """
    from django.core.exceptions import FieldDoesNotExist

    try:
        user._meta.get_field("staff_roles")
    except FieldDoesNotExist:
        return
    roles = staff_roles_for(user)
    if list(user.staff_roles or []) != roles:
        user.staff_roles = roles
        user.save(update_fields=["staff_roles"])


def staff_roles_for(user) -> list[str]:
    """Materialized role names of *user*, sorted (stable claim ordering)."""
    if _is_unsaved(user):
        return []
    return sorted(
        user.staff_role_assignments.values_list("role_name", flat=True)
    )


def assign_staff_role(user, role_name: str, assigned_by=None):
    """Assign *role_name* to *user*. Returns ``(assignment, created)``.

    Idempotent: an existing assignment is returned unchanged and no event is
    emitted. Validates the name against the effective role registry and the
    target against staff status (see the exception docstrings). The row and
    its ``staff.role.assigned`` outbox event commit atomically.
    """
    if role_name not in _registry_roles():
        raise UnknownStaffRoleError(
            f"unknown staff role {role_name!r} — define it in "
            f"STAPEL_ACCESS['ROLES'] (deploy config) before assigning"
        )
    if not (user.is_staff or user.is_superuser):
        raise StaffRoleTargetNotStaffError(
            f"user {user.pk} is not staff — staff roles are assigned to "
            f"staff accounts only (make the user staff first)"
        )

    from stapel_core.comm import emit

    from stapel_auth.events import EVENT_STAFF_ROLE_ASSIGNED
    from stapel_auth.models import StaffRoleAssignment

    with transaction.atomic():
        assignment, created = StaffRoleAssignment.objects.get_or_create(
            user=user,
            role_name=role_name,
            defaults={"assigned_by": assigned_by},
        )
        if created:
            _materialize_field(user)
            emit(
                EVENT_STAFF_ROLE_ASSIGNED,
                {
                    "user_id": str(user.pk),
                    "role": role_name,
                    "staff_roles": staff_roles_for(user),
                    "actor_id": str(assigned_by.pk) if assigned_by else None,
                },
                key=str(user.pk),
                service="auth",
            )
    return assignment, created


def revoke_staff_role(user, role_name: str, revoked_by=None) -> bool:
    """Revoke *role_name* from *user*. Returns True when a row was removed.

    The deletion and its ``staff.role.revoked`` outbox event commit
    atomically. Revoking a role the user does not hold is a no-op (False,
    no event).
    """
    from stapel_core.comm import emit

    from stapel_auth.events import EVENT_STAFF_ROLE_REVOKED
    from stapel_auth.models import StaffRoleAssignment

    with transaction.atomic():
        deleted, _ = StaffRoleAssignment.objects.filter(
            user=user, role_name=role_name
        ).delete()
        if deleted:
            _materialize_field(user)
            emit(
                EVENT_STAFF_ROLE_REVOKED,
                {
                    "user_id": str(user.pk),
                    "role": role_name,
                    "staff_roles": staff_roles_for(user),
                    "actor_id": str(revoked_by.pk) if revoked_by else None,
                },
                key=str(user.pk),
                service="auth",
            )
    return bool(deleted)


def serialize_user_to_jwt_data(user) -> dict:
    """Core JWT payload + the ``staff_roles`` claim (staff tokens only).

    Non-staff tokens carry no claim at all (admin-suite §4: the claim is
    deliberately staff-narrow; client/workspace roles are другой домен).
    Staff tokens always carry the claim — an empty list included — because
    the empty list is the authoritative "zero roles" that consumer sync-down
    (REPLACE, в.3) needs to make revocation land.
    """
    from stapel_core.django.jwt.utils import serialize_user_to_jwt_data as core_serialize

    data = core_serialize(user)
    if data.get("is_staff") or data.get("is_superuser"):
        roles = staff_roles_for(user)
        joined = sum(len(name) for name in roles)
        if joined > CLAIM_SIZE_WARN_CHARS:
            logger.warning(
                "staff_roles claim for user %s is unusually large "
                "(%d roles, %d chars) — check role assignment hygiene",
                user.pk, len(roles), joined,
            )
        data["staff_roles"] = roles
    return data


def create_tokens_for_user(user) -> tuple[str, str]:
    """``(access, refresh)`` token pair carrying the staff_roles claim.

    Drop-in replacement for ``jwt_provider.create_tokens(user)`` — every
    token-issuance path in stapel-auth goes through here so the claim can
    never be forgotten on a new login flow.
    """
    from stapel_core.django.jwt.provider import jwt_provider

    return jwt_provider.create_tokens_from_data(serialize_user_to_jwt_data(user))


def assignment_roles(user) -> list[str] | None:
    """``ROLE_SOURCES`` source reading the assignment table (auth service).

    Returns an authoritative list (empty included) for persisted users —
    on the auth service the table IS the source of truth, fresher than any
    claim. Abstains (None) for unsaved/anonymous users.
    """
    if _is_unsaved(user):
        return None
    return staff_roles_for(user)
