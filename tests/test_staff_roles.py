"""Staff role transport — admin-suite AS-2 (stapel_auth.staff_roles).

Covers, end to end on the auth (producer) side:

- assignment/revocation services: single-writer table, registry validation,
  staff-only targets, idempotency, outbox audit events in the same
  transaction as the row change;
- the ``staff_roles`` JWT claim: present on every staff token (empty list
  included — authoritative-empty is what makes revocation propagate under
  consumer REPLACE sync-down), absent on non-staff tokens (old-token shape:
  consumers must not touch local state for claim-less tokens);
- issuance surfaces: /token/ obtain, /token/refresh/ (fresh claim on every
  refresh — revocation latency ≤ access-token lifetime, invariant A3),
  TokenService, _issue_session_tokens;
- the management API and Django admin, including the AS-1 mandate
  integration (clearance HIGH gates assignment management).

The consumer-side sync-down (REPLACE into the local user copy +
``_stapel_staff_roles_claim`` stamping) lives in stapel-core's
``get_or_create_user_from_jwt`` and is tested there.
"""
import json
import uuid

from django.contrib import admin as django_admin
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from stapel_core.django.jwt.provider import jwt_provider
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.models import StaffRoleAssignment
from stapel_auth.staff_roles import (
    StaffRoleTargetNotStaffError,
    UnknownStaffRoleError,
    assign_staff_role,
    assignment_roles,
    create_tokens_for_user,
    revoke_staff_role,
    serialize_user_to_jwt_data,
    staff_roles_for,
)


def _make_user(**kwargs):
    from django.contrib.auth import get_user_model

    defaults = dict(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password="testpass123!",
    )
    defaults.update(kwargs)
    return get_user_model().objects.create_user(**defaults)


def _event_payloads(topic):
    return [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic=topic).order_by("created_at")
    ]


def _decode(token):
    return jwt_provider.handler.decode_token(token, verify=False) or {}


# =============================================================================
# Model
# =============================================================================


class StaffRoleAssignmentModelTests(TestCase):
    def test_str(self):
        user = _make_user(is_staff=True)
        assignment = StaffRoleAssignment.objects.create(user=user, role_name="editor")
        self.assertIn("editor", str(assignment))

    def test_unique_per_user_and_role(self):
        from django.db import IntegrityError

        user = _make_user(is_staff=True)
        StaffRoleAssignment.objects.create(user=user, role_name="editor")
        with self.assertRaises(IntegrityError):
            StaffRoleAssignment.objects.create(user=user, role_name="editor")

    def test_access_declaration_is_all_high(self):
        # Managing assignments is itself a HIGH-clearance operation
        # (admin-suite §3.3) — the @access declaration is the enforcement
        # input for AS-1's MandateBackend and AS-3's admin visibility.
        from stapel_core.access import Level, declared_access

        declaration = declared_access(StaffRoleAssignment)
        self.assertEqual(declaration.category, "business")
        for action in ("view", "add", "change", "delete"):
            self.assertEqual(declaration.required(action), Level.HIGH)


# =============================================================================
# Services (single writer, A2) + outbox audit events (S6)
# =============================================================================


class AssignStaffRoleTests(TestCase):
    def setUp(self):
        self.user = _make_user(is_staff=True)
        self.actor = _make_user(is_staff=True, is_superuser=True)

    def test_assign_creates_row_and_emits_event(self):
        assignment, created = assign_staff_role(
            self.user, "editor", assigned_by=self.actor
        )
        self.assertTrue(created)
        self.assertEqual(assignment.assigned_by, self.actor)
        payloads = _event_payloads("staff.role.assigned")
        self.assertEqual(len(payloads), 1)
        self.assertEqual(
            payloads[0],
            {
                "user_id": str(self.user.pk),
                "role": "editor",
                "staff_roles": ["editor"],
                "actor_id": str(self.actor.pk),
            },
        )

    def test_assign_is_idempotent_no_second_event(self):
        assign_staff_role(self.user, "editor")
        assignment, created = assign_staff_role(self.user, "editor")
        self.assertFalse(created)
        self.assertEqual(StaffRoleAssignment.objects.filter(user=self.user).count(), 1)
        self.assertEqual(len(_event_payloads("staff.role.assigned")), 1)

    def test_assign_without_actor_has_null_actor_id(self):
        assign_staff_role(self.user, "viewer")
        payloads = _event_payloads("staff.role.assigned")
        self.assertIsNone(payloads[0]["actor_id"])

    def test_unknown_role_rejected_no_row_no_event(self):
        with self.assertRaises(UnknownStaffRoleError):
            assign_staff_role(self.user, "warlord")
        self.assertFalse(StaffRoleAssignment.objects.exists())
        self.assertEqual(_event_payloads("staff.role.assigned"), [])

    def test_custom_registry_role_accepted(self):
        with override_settings(
            STAPEL_ACCESS={"ROLES": {"accountant": {"clearance": "low"}}}
        ):
            _, created = assign_staff_role(self.user, "accountant")
        self.assertTrue(created)

    def test_non_staff_target_rejected(self):
        # Dormant-privilege guard: a role parked on a non-staff account
        # would silently activate the day is_staff is flipped.
        civilian = _make_user()
        with self.assertRaises(StaffRoleTargetNotStaffError):
            assign_staff_role(civilian, "editor")
        self.assertFalse(StaffRoleAssignment.objects.exists())

    def test_superuser_target_allowed_even_without_is_staff(self):
        root = _make_user(is_superuser=True)
        _, created = assign_staff_role(root, "editor")
        self.assertTrue(created)

    def test_event_payload_lists_all_roles_after_change(self):
        assign_staff_role(self.user, "editor")
        assign_staff_role(self.user, "admin")
        payloads = _event_payloads("staff.role.assigned")
        self.assertEqual(payloads[1]["staff_roles"], ["admin", "editor"])


class RevokeStaffRoleTests(TestCase):
    def setUp(self):
        self.user = _make_user(is_staff=True)
        self.actor = _make_user(is_staff=True, is_superuser=True)
        assign_staff_role(self.user, "editor")
        assign_staff_role(self.user, "admin")

    def test_revoke_removes_row_and_emits_event(self):
        removed = revoke_staff_role(self.user, "editor", revoked_by=self.actor)
        self.assertTrue(removed)
        payloads = _event_payloads("staff.role.revoked")
        self.assertEqual(
            payloads[0],
            {
                "user_id": str(self.user.pk),
                "role": "editor",
                "staff_roles": ["admin"],  # the list AFTER the change
                "actor_id": str(self.actor.pk),
            },
        )

    def test_revoke_missing_role_is_noop(self):
        removed = revoke_staff_role(self.user, "viewer")
        self.assertFalse(removed)
        self.assertEqual(_event_payloads("staff.role.revoked"), [])

    def test_revoke_without_actor_has_null_actor_id(self):
        revoke_staff_role(self.user, "editor")
        self.assertIsNone(_event_payloads("staff.role.revoked")[0]["actor_id"])


class MaterializeFieldTests(TestCase):
    """`_materialize_field` mirrors the assignment table into the user's
    ``staff_roles`` JSON field when the model has one (the stapel-core AS-2
    counterpart adds it to AbstractStapelUser). Core-side token paths
    (load_user_by_uid, middleware proactive refresh) serialize from that
    field — keeping it in sync in the same transaction closes the
    stale-claim re-mint window."""

    def test_noop_when_user_model_has_no_field(self):
        # The current users.User has no staff_roles field: assignment writes
        # must succeed without touching the user row.
        user = _make_user(is_staff=True)
        assign_staff_role(user, "editor")  # would raise if it tried to save the field
        self.assertEqual(staff_roles_for(user), ["editor"])

    def _field_user(self, current):
        from unittest import mock

        user = mock.Mock()
        user.staff_roles = current
        user._meta.get_field.return_value = object()  # field exists
        return user

    def test_writes_field_when_out_of_sync(self):
        from unittest import mock

        from stapel_auth.staff_roles import _materialize_field

        user = self._field_user(current=["old"])
        with mock.patch(
            "stapel_auth.staff_roles.staff_roles_for", return_value=["editor"]
        ):
            _materialize_field(user)
        self.assertEqual(user.staff_roles, ["editor"])
        user.save.assert_called_once_with(update_fields=["staff_roles"])

    def test_skips_save_when_already_in_sync(self):
        from unittest import mock

        from stapel_auth.staff_roles import _materialize_field

        user = self._field_user(current=["editor"])
        with mock.patch(
            "stapel_auth.staff_roles.staff_roles_for", return_value=["editor"]
        ):
            _materialize_field(user)
        user.save.assert_not_called()


class RoleReadersTests(TestCase):
    def test_staff_roles_for_is_sorted(self):
        user = _make_user(is_staff=True)
        assign_staff_role(user, "editor")
        assign_staff_role(user, "admin")
        self.assertEqual(staff_roles_for(user), ["admin", "editor"])

    def test_staff_roles_for_empty(self):
        self.assertEqual(staff_roles_for(_make_user(is_staff=True)), [])

    def test_staff_roles_for_unsaved_user(self):
        from django.contrib.auth import get_user_model

        self.assertEqual(staff_roles_for(get_user_model()()), [])
        self.assertEqual(staff_roles_for(None), [])

    def test_assignment_roles_authoritative_for_persisted_users(self):
        # ROLE_SOURCES semantics: a list — even empty — terminates the
        # chain. On the auth service the table is the source of truth.
        user = _make_user(is_staff=True)
        self.assertEqual(assignment_roles(user), [])
        assign_staff_role(user, "editor")
        self.assertEqual(assignment_roles(user), ["editor"])

    def test_assignment_roles_abstains_for_unsaved_user(self):
        from django.contrib.auth import get_user_model

        self.assertIsNone(assignment_roles(get_user_model()()))
        self.assertIsNone(assignment_roles(None))


# =============================================================================
# JWT claim
# =============================================================================


class StaffRolesClaimTests(TestCase):
    def test_staff_with_roles_gets_sorted_claim(self):
        user = _make_user(is_staff=True)
        assign_staff_role(user, "editor")
        assign_staff_role(user, "admin")
        data = serialize_user_to_jwt_data(user)
        self.assertEqual(data["staff_roles"], ["admin", "editor"])

    def test_staff_without_roles_gets_empty_claim(self):
        # Authoritative-empty: the empty list must ride the token so that
        # consumer REPLACE sync-down can land a revocation (в.3).
        data = serialize_user_to_jwt_data(_make_user(is_staff=True))
        self.assertEqual(data["staff_roles"], [])

    def test_non_staff_token_has_no_claim(self):
        # Claim-less token == pre-AS-2 token shape: consumers treat the
        # absence as "no information" and must not touch local roles.
        data = serialize_user_to_jwt_data(_make_user())
        self.assertNotIn("staff_roles", data)

    def test_superuser_without_is_staff_gets_claim(self):
        data = serialize_user_to_jwt_data(_make_user(is_superuser=True))
        self.assertEqual(data["staff_roles"], [])

    def test_oversized_claim_logs_warning_but_still_serializes(self):
        user = _make_user(is_staff=True)
        big_roles = {f"role_{i}_{'x' * 120}": {"clearance": "low"} for i in range(6)}
        with override_settings(STAPEL_ACCESS={"ROLES": big_roles}):
            for name in big_roles:
                assign_staff_role(user, name)
            with self.assertLogs("stapel_auth.staff_roles", level="WARNING") as logs:
                data = serialize_user_to_jwt_data(user)
        self.assertEqual(len(data["staff_roles"]), 6)
        self.assertIn("unusually large", logs.output[0])

    def test_create_tokens_for_user_embeds_claim_in_both_tokens(self):
        user = _make_user(is_staff=True)
        assign_staff_role(user, "editor")
        access, refresh = create_tokens_for_user(user)
        self.assertEqual(_decode(access)["staff_roles"], ["editor"])
        self.assertEqual(_decode(refresh)["staff_roles"], ["editor"])


# =============================================================================
# Issuance surfaces
# =============================================================================


class TokenEndpointClaimTests(APITestCase):
    def setUp(self):
        self.password = "S3curePass!x"
        self.user = _make_user(is_staff=True, password=self.password)
        assign_staff_role(self.user, "editor")

    def _obtain_pair(self):
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"username": self.user.username, "password": self.password},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        return resp.data["access"], resp.data["refresh"]

    def test_obtain_pair_carries_claim(self):
        access, refresh = self._obtain_pair()
        self.assertEqual(_decode(access)["staff_roles"], ["editor"])
        self.assertEqual(_decode(refresh)["staff_roles"], ["editor"])

    def test_refresh_picks_up_new_assignment(self):
        _, refresh = self._obtain_pair()
        assign_staff_role(self.user, "admin")
        resp = self.client.post(
            reverse("token_refresh"), {"refresh": refresh}, format="json"
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertEqual(
            _decode(resp.data["access"])["staff_roles"], ["admin", "editor"]
        )

    def test_refresh_after_revocation_carries_empty_claim(self):
        # Revocation lands on the next refresh: the new access token says
        # "zero roles" authoritatively — a consumer syncing down REPLACEs
        # its local copy with the empty list (A3).
        _, refresh = self._obtain_pair()
        revoke_staff_role(self.user, "editor")
        resp = self.client.post(
            reverse("token_refresh"), {"refresh": refresh}, format="json"
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertEqual(_decode(resp.data["access"])["staff_roles"], [])

    def test_non_staff_obtain_pair_has_no_claim(self):
        civilian = _make_user(password=self.password)
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"username": civilian.username, "password": self.password},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.content)
        self.assertNotIn("staff_roles", _decode(resp.data["access"]))


class TokenServiceClaimTests(TestCase):
    def setUp(self):
        self.user = _make_user(is_staff=True)
        assign_staff_role(self.user, "viewer")

    def test_token_service_create_tokens_for_user(self):
        from stapel_auth.sessions.services import TokenService

        tokens = TokenService.create_tokens_for_user(self.user)
        self.assertEqual(_decode(tokens["access"])["staff_roles"], ["viewer"])

    def test_token_service_get_refresh_token_for_user(self):
        from stapel_auth.sessions.services import TokenService

        pair = TokenService.get_refresh_token_for_user(self.user)
        self.assertEqual(_decode(str(pair.access_token))["staff_roles"], ["viewer"])

    def test_issue_session_tokens_carries_claim(self):
        from stapel_auth.sessions.views import _issue_session_tokens

        access, refresh = _issue_session_tokens(self.user, request=None)
        self.assertEqual(_decode(access)["staff_roles"], ["viewer"])
        self.assertEqual(_decode(refresh)["staff_roles"], ["viewer"])


# =============================================================================
# Management API
# =============================================================================


class StaffRoleAPITests(APITestCase):
    def setUp(self):
        self.root = _make_user(is_staff=True, is_superuser=True)
        self.target = _make_user(is_staff=True)
        access, _ = create_tokens_for_user(self.root)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

    def _assign(self, **overrides):
        body = {"user_id": str(self.target.pk), "role": "editor"}
        body.update(overrides)
        return self.client.post(reverse("staff-roles"), body, format="json")

    def test_assign_created_then_idempotent(self):
        resp = self._assign()
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)
        self.assertEqual(resp.data["role_name"], "editor")
        resp2 = self._assign()
        self.assertEqual(resp2.status_code, status.HTTP_200_OK)
        self.assertEqual(len(_event_payloads("staff.role.assigned")), 1)

    def test_assign_unknown_role_400(self):
        resp = self._assign(role="warlord")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("unknown_staff_role", str(resp.data))

    def test_assign_to_non_staff_400(self):
        civilian = _make_user()
        resp = self._assign(user_id=str(civilian.pk))
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("staff_role_target_not_staff", str(resp.data))

    def test_assign_to_missing_user_404(self):
        resp = self._assign(user_id=str(uuid.uuid4()))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_list_and_filter(self):
        other = _make_user(is_staff=True)
        assign_staff_role(self.target, "editor")
        assign_staff_role(other, "viewer")
        resp = self.client.get(reverse("staff-roles"))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data), 2)
        resp = self.client.get(
            reverse("staff-roles"), {"user_id": str(self.target.pk)}
        )
        self.assertEqual([row["role_name"] for row in resp.data], ["editor"])

    def test_revoke_by_assignment_id(self):
        assignment, _ = assign_staff_role(self.target, "editor")
        resp = self.client.delete(
            reverse("staff-role-detail", args=[assignment.pk])
        )
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(StaffRoleAssignment.objects.exists())
        payloads = _event_payloads("staff.role.revoked")
        self.assertEqual(payloads[0]["role"], "editor")
        self.assertEqual(payloads[0]["actor_id"], str(self.root.pk))

    def test_revoke_missing_assignment_404(self):
        resp = self.client.delete(reverse("staff-role-detail", args=[uuid.uuid4()]))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_anonymous_denied(self):
        client = self.client_class()
        self.assertIn(
            client.get(reverse("staff-roles")).status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )

    def test_plain_staff_without_grants_denied(self):
        # Staff without the model permission (no mandate, no DAC grant)
        # cannot touch assignments — never "any staff can grant roles".
        plain = _make_user(is_staff=True)
        access, _ = create_tokens_for_user(plain)
        client = self.client_class()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        self.assertEqual(
            client.get(reverse("staff-roles")).status_code,
            status.HTTP_403_FORBIDDEN,
        )
        resp = client.post(
            reverse("staff-roles"),
            {"user_id": str(self.target.pk), "role": "editor"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        assignment, _ = assign_staff_role(self.target, "viewer")
        self.assertEqual(
            client.delete(
                reverse("staff-role-detail", args=[assignment.pk])
            ).status_code,
            status.HTTP_403_FORBIDDEN,
        )


_MANDATE_BACKENDS = [
    "stapel_core.access.backend.MandateBackend",
    "stapel_core.access.backend.AuditedModelBackend",
]

_AUTH_ROLE_SOURCES = {
    "ROLE_SOURCES": [
        "stapel_auth.staff_roles.assignment_roles",
        "stapel_core.access.sources.claim_roles",
        "stapel_core.access.sources.group_roles",
    ],
}


@override_settings(
    AUTHENTICATION_BACKENDS=_MANDATE_BACKENDS, STAPEL_ACCESS=_AUTH_ROLE_SOURCES
)
class StaffRoleAPIMandateIntegrationTests(APITestCase):
    """AS-1 × AS-2: with the mandate backends installed on the auth service,
    role assignments in the auth DB gate the assignment API itself —
    clearance HIGH manages roles, clearance MID does not."""

    def setUp(self):
        self.target = _make_user(is_staff=True)

    def _client_for(self, user):
        access, _ = create_tokens_for_user(user)
        client = self.client_class()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return client

    def test_high_clearance_staff_can_manage_assignments(self):
        manager = _make_user(is_staff=True)
        assign_staff_role(manager, "admin")  # builtin admin = HIGH
        client = self._client_for(manager)
        self.assertEqual(
            client.get(reverse("staff-roles")).status_code, status.HTTP_200_OK
        )
        resp = client.post(
            reverse("staff-roles"),
            {"user_id": str(self.target.pk), "role": "editor"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED, resp.content)

    def test_mid_clearance_staff_denied(self):
        moderator = _make_user(is_staff=True)
        assign_staff_role(moderator, "editor")  # builtin editor = MID
        client = self._client_for(moderator)
        self.assertEqual(
            client.get(reverse("staff-roles")).status_code,
            status.HTTP_403_FORBIDDEN,
        )
        resp = client.post(
            reverse("staff-roles"),
            {"user_id": str(self.target.pk), "role": "editor"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)


# =============================================================================
# Django admin
# =============================================================================


class StaffRoleAdminTests(TestCase):
    def setUp(self):
        from django.test import RequestFactory

        self.model_admin = django_admin.site._registry[StaffRoleAssignment]
        self.actor = _make_user(is_staff=True, is_superuser=True)
        self.user = _make_user(is_staff=True)
        request = RequestFactory().post("/admin/")
        request.user = self.actor
        self.request = request

    def test_registered_and_immutable(self):
        self.assertFalse(self.model_admin.has_change_permission(self.request))

    def test_form_rejects_unknown_role(self):
        from stapel_auth.admin import StaffRoleAssignmentForm

        form = StaffRoleAssignmentForm(
            data={"user": self.user.pk, "role_name": "warlord"}
        )
        self.assertFalse(form.is_valid())
        self.assertIn("Unknown staff role", str(form.errors))

    def test_form_rejects_non_staff_target(self):
        from stapel_auth.admin import StaffRoleAssignmentForm

        civilian = _make_user()
        form = StaffRoleAssignmentForm(
            data={"user": civilian.pk, "role_name": "editor"}
        )
        self.assertFalse(form.is_valid())
        self.assertIn("staff accounts", str(form.errors))

    def test_form_accepts_registry_role_for_staff(self):
        from stapel_auth.admin import StaffRoleAssignmentForm

        form = StaffRoleAssignmentForm(
            data={"user": self.user.pk, "role_name": "editor"}
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_save_model_routes_through_service(self):
        obj = StaffRoleAssignment(user=self.user, role_name="editor")
        self.model_admin.save_model(self.request, obj, form=None, change=False)
        assignment = StaffRoleAssignment.objects.get()
        self.assertEqual(obj.pk, assignment.pk)
        self.assertEqual(assignment.assigned_by, self.actor)
        payloads = _event_payloads("staff.role.assigned")
        self.assertEqual(payloads[0]["actor_id"], str(self.actor.pk))

    def test_delete_model_routes_through_service(self):
        assignment, _ = assign_staff_role(self.user, "editor")
        self.model_admin.delete_model(self.request, assignment)
        self.assertFalse(StaffRoleAssignment.objects.exists())
        self.assertEqual(len(_event_payloads("staff.role.revoked")), 1)

    def test_delete_queryset_routes_through_service(self):
        assign_staff_role(self.user, "editor")
        assign_staff_role(self.user, "viewer")
        self.model_admin.delete_queryset(
            self.request, StaffRoleAssignment.objects.all()
        )
        self.assertFalse(StaffRoleAssignment.objects.exists())
        self.assertEqual(len(_event_payloads("staff.role.revoked")), 2)


# =============================================================================
# Events registry
# =============================================================================


class StaffRoleEventRegistryTests(TestCase):
    def test_constants_and_registry(self):
        from stapel_auth import events

        self.assertEqual(events.EVENT_STAFF_ROLE_ASSIGNED, "staff.role.assigned")
        self.assertEqual(events.EVENT_STAFF_ROLE_REVOKED, "staff.role.revoked")
        self.assertIs(
            events.EVENT_REGISTRY["staff.role.assigned"],
            events.StaffRoleAssignedPayload,
        )
        self.assertIs(
            events.EVENT_REGISTRY["staff.role.revoked"],
            events.StaffRoleRevokedPayload,
        )

    def test_payload_dataclasses(self):
        from stapel_auth.events import (
            StaffRoleAssignedPayload,
            StaffRoleRevokedPayload,
        )

        assigned = StaffRoleAssignedPayload(user_id="u", role="editor")
        self.assertEqual(assigned.staff_roles, [])
        self.assertIsNone(assigned.actor_id)
        revoked = StaffRoleRevokedPayload(
            user_id="u", role="editor", staff_roles=["admin"], actor_id="a"
        )
        self.assertEqual(revoked.staff_roles, ["admin"])


class StaffRolePackageExportTests(TestCase):
    def test_lazy_exports(self):
        import stapel_auth

        self.assertIs(stapel_auth.assign_staff_role, assign_staff_role)
        self.assertIs(stapel_auth.revoke_staff_role, revoke_staff_role)
        self.assertIs(stapel_auth.staff_roles_for, staff_roles_for)
