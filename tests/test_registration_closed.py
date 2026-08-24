"""Closed registration — the owner keeps the only key (#86).

The deployment wants one thing: **nobody signs themselves up, everybody who
is already here keeps signing in.** The ``AUTH_*_REGISTRATION`` settings
have always claimed to do that, and could not: their check sat on the
*request-a-code* handler and read ``not LOGIN and not REGISTRATION``, so it
fired only when the whole channel was off. With login on and registration
off — the exact configuration this feature is for — the endpoint accepted
any address, mailed a code, and ``email_verify`` ran an unconditional
``User.objects.create``. Same for phone. OAuth and SSO never consulted their
axes at all.

So these tests are written against the *outcome*, not the plumbing: with
registration closed, no stranger gets an account **by any door**, and every
member still gets in **through every door**. And the owner's own doors —
``auth.provision_user``, ``POST /admin-users/``, a service-minted login
grant — keep working, because a deployment with all four axes off and no
provisioning left would have no way to create accounts at all.

The third group covers the choice the axes force on us: refusing only
*unknown* addresses turns the OTP endpoints into an existence oracle. All
three honest behaviors are supported (``AUTH_REGISTRATION_CLOSED_BEHAVIOR``)
and the default is the one that leaks nothing; see registration.py for the
argument.
"""
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from stapel_core.comm import call

from stapel_auth.errors import ERR_400_INVALID_CODE, ERR_403_REGISTRATION_CLOSED
from stapel_auth.models import Organization
from stapel_auth.oauth_providers import OAuthUserData
from stapel_auth.registration import RegistrationClosed
from stapel_auth.sso_service import SSOUserService

User = get_user_model()

MOCK_CODE = "0000"

#: Registration shut everywhere. ``*_LOGIN`` stays at its default (on) —
#: that IS the scenario: the doors open, the registry closed.
ALL_CLOSED = {
    "AUTH_EMAIL_REGISTRATION": False,
    "AUTH_PHONE_REGISTRATION": False,
    "AUTH_OAUTH_REGISTRATION": False,
    "AUTH_SSO_REGISTRATION": False,
    "AUTH_PASSWORD_REGISTRATION": False,
}


def _closed(**extra):
    return {**ALL_CLOSED, **extra}


def _slug() -> str:
    return f"org{uuid.uuid4().hex[:8]}"


# ─────────────────────────────────────────────────────────────────────────────
# 1. No stranger gets an account — by any door
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(URL_PREFIX="", STAPEL_AUTH=_closed(
    AUTH_REGISTRATION_CLOSED_BEHAVIOR="verify",
))
class ClosedRegistrationRefusesNewAccountsTests(APITestCase):
    """'verify' mode is used here so the refusal is *named* on every path and
    the assertion is about the account, not about the disguise. The disguise
    (the default 'silent' mode) has its own tests further down."""

    def test_email_otp_does_not_create_an_account(self):
        before = User.objects.count()
        req = self.client.post(reverse("email_request"), {"email": "stranger@example.com"})
        self.assertEqual(req.status_code, status.HTTP_200_OK)

        resp = self.client.post(
            reverse("email_verify"),
            {"email": "stranger@example.com", "code": MOCK_CODE},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data["localizable_error"], ERR_403_REGISTRATION_CLOSED)
        self.assertFalse(User.objects.filter(email="stranger@example.com").exists())
        self.assertEqual(User.objects.count(), before)

    def test_phone_otp_does_not_create_an_account(self):
        before = User.objects.count()
        req = self.client.post(reverse("phone_request"), {"phone": "+12025550111"})
        self.assertEqual(req.status_code, status.HTTP_200_OK)

        resp = self.client.post(
            reverse("phone_verify"), {"phone": "+12025550111", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data["localizable_error"], ERR_403_REGISTRATION_CLOSED)
        self.assertFalse(User.objects.filter(phone="+12025550111").exists())
        self.assertEqual(User.objects.count(), before)

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_oauth_does_not_create_an_account(self, mock_user_data):
        mock_user_data.return_value = OAuthUserData(
            id="google-stranger-1",
            email="stranger-oauth@example.com",
            username="Stranger",
            avatar=None,
        )
        before = User.objects.count()
        resp = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-token"},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data["localizable_error"], ERR_403_REGISTRATION_CLOSED)
        self.assertFalse(User.objects.filter(email="stranger-oauth@example.com").exists())
        self.assertEqual(User.objects.count(), before)

    def test_oauth_does_not_promote_a_guest_session(self):
        """The guest row is an account-in-waiting; attaching an OAuth anchor
        to it registers just as surely as creating a fresh row does."""
        guest = self.client.post(reverse("anonymous"), {})
        self.assertEqual(guest.status_code, status.HTTP_201_CREATED)
        guest_id = guest.data["user"]["id"]
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {guest.data['tokens']['access']}"
        )
        with patch(
            "stapel_auth.oauth.services.OAuthService.get_user_data",
            return_value=OAuthUserData(
                id="google-guest-1",
                email="guest-oauth@example.com",
                username="Guest",
                avatar=None,
            ),
        ):
            resp = self.client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "fake-token"},
            )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        still_guest = User.objects.get(pk=guest_id)
        self.assertTrue(still_guest.is_anonymous)
        self.assertFalse(User.objects.filter(email="guest-oauth@example.com").exists())

    def test_sso_jit_provisioning_does_not_create_an_account(self):
        org = Organization.objects.create(name="Acme", slug=_slug(), domain="acme.test")
        attrs = {
            "email": "stranger-sso@acme.test",
            "first_name": "S",
            "last_name": "S",
            "subject_id": "sub-stranger",
        }
        with self.assertRaises(RegistrationClosed):
            SSOUserService.get_or_create_user(org, attrs)
        self.assertFalse(User.objects.filter(email="stranger-sso@acme.test").exists())

    def test_sso_acs_lands_on_the_login_screen_with_a_reason(self):
        """A browser navigation from the IdP must not end on a JSON body."""
        org = Organization.objects.create(name="Acme", slug="acmeclosed", domain="acmeclosed.test")
        from stapel_auth.models import SSOConfig

        SSOConfig.objects.create(
            org=org,
            protocol=SSOConfig.PROTOCOL_SAML,
            is_active=True,
            saml_entity_id="https://idp.acmeclosed.test",
            saml_sso_url="https://idp.acmeclosed.test/sso",
            saml_x509_cert="MIID...",
        )
        attrs = {
            "email": "newhire@acmeclosed.test",
            "first_name": "New",
            "last_name": "Hire",
            "subject_id": "sub-nh",
        }
        from stapel_auth.sso_service import SAMLService

        with patch.object(SAMLService, "parse_response", return_value=attrs):
            resp = self.client.post(
                reverse("sso_saml_acs", kwargs={"slug": "acmeclosed"}),
                {"SAMLResponse": "irrelevant-parse-is-patched"},
            )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=registration_closed", resp["Location"])
        self.assertFalse(User.objects.filter(email="newhire@acmeclosed.test").exists())

    def test_password_register_is_refused(self):
        resp = self.client.post(
            reverse("password_register"),
            {"email": "stranger-pw@example.com", "password": "correct-horse-battery-9"},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(User.objects.filter(email="stranger-pw@example.com").exists())


# ─────────────────────────────────────────────────────────────────────────────
# 2. Everybody already here still gets in — through every door
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(URL_PREFIX="", STAPEL_AUTH=_closed(
    AUTH_REGISTRATION_CLOSED_BEHAVIOR="verify",
))
class ClosedRegistrationKeepsLoginWorkingTests(APITestCase):
    """The half that makes the feature usable: closing sign-up must not be a
    disguised outage. Each existing account signs in exactly as before."""

    def setUp(self):
        self.member = User.objects.create_user(
            username="member",
            email="member@example.com",
            password="testpass123",
            phone="+12025550222",
            is_email_verified=True,
            is_phone_verified=True,
        )
        self.oauth_member = User.objects.create_user(
            username="oauthmember",
            email="oauthmember@example.com",
            password="testpass123",
            oauth_provider="google",
            oauth_id="google-member-1",
        )

    def test_email_otp_login(self):
        self.assertEqual(
            self.client.post(
                reverse("email_request"), {"email": "member@example.com"}
            ).status_code,
            status.HTTP_200_OK,
        )
        resp = self.client.post(
            reverse("email_verify"), {"email": "member@example.com", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "LOGGED_IN")

    def test_phone_otp_login(self):
        self.assertEqual(
            self.client.post(
                reverse("phone_request"), {"phone": "+12025550222"}
            ).status_code,
            status.HTTP_200_OK,
        )
        resp = self.client.post(
            reverse("phone_verify"), {"phone": "+12025550222", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "LOGGED_IN")

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_oauth_login(self, mock_user_data):
        mock_user_data.return_value = OAuthUserData(
            id="google-member-1",
            email="oauthmember@example.com",
            username="Member",
            avatar=None,
        )
        resp = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-token"},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "LOGGED_IN")

    def test_sso_login_for_an_existing_account(self):
        # The org owns the member's address namespace — since 0.21 that is
        # what lets an SSO login claim an account that already exists (see
        # tests/test_sso_fail_closed.py); the domain used to be decorative.
        org = Organization.objects.create(name="Acme", slug=_slug(), domain="example.com")
        user, created = SSOUserService.get_or_create_user(
            org,
            {
                "email": "member@example.com",
                "first_name": "",
                "last_name": "",
                "subject_id": "sub-member",
            },
        )
        self.assertFalse(created)
        self.assertEqual(user.pk, self.member.pk)

    def test_authenticated_member_can_still_change_their_own_email(self):
        """A change is not a registration: the account already exists and no
        new row appears. Gating it would have been the obvious over-reach.

        Driven through the change flow, which is where replacing a VERIFIED
        address lives (audit F4) — the point under test is that the closed
        registration gate does not reach into it.
        """
        from stapel_auth.tests.test_auth import create_token_for_user

        access, _ = create_token_for_user(self.member)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        before = User.objects.count()

        self.client.post(reverse("email_instant_request_old"), {})
        old_verified = self.client.post(
            reverse("email_instant_verify_old"), {"code": MOCK_CODE}
        )
        self.assertEqual(old_verified.status_code, status.HTTP_200_OK, old_verified.data)
        token = old_verified.data["change_token"]

        req = self.client.post(
            reverse("email_instant_request_new"),
            {"email": "member-new@example.com", "change_token": token},
        )
        self.assertEqual(req.status_code, status.HTTP_200_OK, req.data)
        resp = self.client.post(
            reverse("email_instant_verify_new"),
            {
                "email": "member-new@example.com",
                "code": MOCK_CODE,
                "change_token": token,
            },
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.data)
        self.assertEqual(resp.data["status"], "MODIFIED")
        self.assertEqual(User.objects.count(), before)
        self.member.refresh_from_db()
        self.assertEqual(self.member.email, "member-new@example.com")


# ─────────────────────────────────────────────────────────────────────────────
# 3. The owner's own doors stay open
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(URL_PREFIX="", STAPEL_AUTH=_closed())
class OwnerProvisioningSurvivesClosedRegistrationTests(APITestCase):
    """Closing self-service must not close the owner out of their own
    deployment — otherwise "only the owner creates accounts" has no owner
    path left and the setting is unusable in production."""

    def test_provision_user_comm_function(self):
        username = f"{_slug()}/alice"
        result = call("auth.provision_user", {
            "username": username,
            "display_name": "Alice A.",
            "first_login_policy": "password_change",
        })
        self.assertNotIn("error", result)
        user = User.objects.get(pk=result["user_id"])
        self.assertEqual(user.username, username)

    def test_admin_user_broker_endpoint(self):
        admin = User.objects.create_user(username="admin", password="pw", is_staff=True)
        from stapel_auth.tests.test_auth import create_token_for_user

        access, _ = create_token_for_user(admin)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        resp = self.client.post(
            reverse("admin-users"), {"email": "hired@example.com"}
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email="hired@example.com").exists())

    def test_service_minted_login_grant(self):
        """A grant is minted server-side by a trusted issuer (the workspaces
        invite flow), never by the person signing in — the owner's door in
        another shape."""
        from stapel_auth.login_grant.services import LoginGrantService, issue_login_grant

        token = issue_login_grant(email="invited@example.com", create_if_missing=True)
        user, created = LoginGrantService.exchange(token)
        self.assertTrue(created)
        self.assertEqual(user.email, "invited@example.com")

    def test_a_provisioned_account_can_then_sign_in(self):
        """End to end: the owner makes the account, the human uses it."""
        User.objects.create_user(
            username="hired", email="hired2@example.com", password="pw",
            is_email_verified=True,
        )
        self.client.post(reverse("email_request"), {"email": "hired2@example.com"})
        resp = self.client.post(
            reverse("email_verify"), {"email": "hired2@example.com", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "LOGGED_IN")


# ─────────────────────────────────────────────────────────────────────────────
# 4. The oracle: what a stranger is allowed to learn
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(URL_PREFIX="", STAPEL_AUTH=_closed())
class SilentBehaviorLeaksNothingTests(APITestCase):
    """Default mode. Member and stranger get the SAME answer on */request/;
    the stranger simply never receives a code, so */verify/ fails the way a
    wrong code fails. Nothing in the exchange separates the two."""

    def setUp(self):
        self.member = User.objects.create_user(
            username="member", email="member@example.com", password="pw",
            phone="+12025550333", is_email_verified=True, is_phone_verified=True,
        )

    def test_default_is_the_closed_one(self):
        from stapel_auth.registration import closed_behavior

        self.assertEqual(closed_behavior(), "silent")

    def test_email_request_answers_member_and_stranger_identically(self):
        member = self.client.post(reverse("email_request"), {"email": "member@example.com"})
        stranger = self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        self.assertEqual(member.status_code, stranger.status_code)
        self.assertEqual(member.status_code, status.HTTP_200_OK)
        # Byte-identical but for the address the caller themselves supplied.
        self.assertEqual(
            member.content.replace(b"member@example.com", b"X"),
            stranger.content.replace(b"nobody@example.com", b"X"),
        )

    def test_phone_request_answers_member_and_stranger_identically(self):
        member = self.client.post(reverse("phone_request"), {"phone": "+12025550333"})
        stranger = self.client.post(reverse("phone_request"), {"phone": "+12025550444"})
        self.assertEqual(member.status_code, stranger.status_code)
        self.assertEqual(member.status_code, status.HTTP_200_OK)
        self.assertEqual(
            member.content.replace(b"+12025550333", b"X"),
            stranger.content.replace(b"+12025550444", b"X"),
        )

    def test_the_stranger_is_never_sent_anything(self):
        """The one asymmetry that is allowed, because it is invisible to the
        caller: no letter leaves the building for an address with no account.
        Mock OTP is on in the test settings, so the *stored* code must also
        stop being the public mock value — otherwise 'undeliverable' would be
        a code everybody knows."""
        from stapel_core.verification.codes import CodeOutcome

        from stapel_auth.otp.services import email_code_store

        with patch("stapel_core.notifications.request_notification") as notify:
            self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        notify.assert_not_called()
        # A code was stored, and it is not the one everybody knows.
        self.assertIs(
            email_code_store.check("nobody@example.com", MOCK_CODE).outcome,
            CodeOutcome.MISMATCH,
        )

    def test_the_mock_code_does_not_open_an_account_for_a_stranger(self):
        self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        resp = self.client.post(
            reverse("email_verify"), {"email": "nobody@example.com", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(email="nobody@example.com").exists())

    def test_verify_refusal_is_indistinguishable_from_a_wrong_code(self):
        """The refusal must not announce itself: a 403 'registration closed'
        here would move the oracle from the request step to the verify step
        rather than removing it."""
        self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        stranger = self.client.post(
            reverse("email_verify"), {"email": "nobody@example.com", "code": "9999"}
        )
        self.assertEqual(stranger.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            stranger.data["localizable_error"],
            (ERR_400_INVALID_CODE, "error.400.invalid_code_attempts"),
        )
        self.assertNotEqual(
            stranger.data["localizable_error"], ERR_403_REGISTRATION_CLOSED
        )

    def test_rate_limiting_is_not_a_side_channel(self):
        """A stranger's second request inside the cooldown must be refused
        exactly like a member's — skipping the record for strangers would
        have handed back the oracle through the 429."""
        self.client.post(reverse("email_request"), {"email": "member@example.com"})
        self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        member = self.client.post(reverse("email_request"), {"email": "member@example.com"})
        stranger = self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        self.assertEqual(member.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(stranger.status_code, member.status_code)


@override_settings(URL_PREFIX="", STAPEL_AUTH=_closed(
    AUTH_REGISTRATION_CLOSED_BEHAVIOR="request",
))
class RequestBehaviorRefusesEarlyTests(APITestCase):
    """The usable-but-enumerable option: say so at once, send nothing."""

    def setUp(self):
        self.member = User.objects.create_user(
            username="member", email="member@example.com", password="pw",
            is_email_verified=True,
        )

    def test_stranger_is_refused_at_request(self):
        from stapel_core.verification.codes import CodeOutcome

        from stapel_auth.otp.services import email_code_store

        resp = self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data["localizable_error"], ERR_403_REGISTRATION_CLOSED)
        self.assertIs(
            email_code_store.check("nobody@example.com", MOCK_CODE).outcome,
            CodeOutcome.NOT_FOUND,
        )

    def test_member_is_untouched(self):
        resp = self.client.post(reverse("email_request"), {"email": "member@example.com"})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)


@override_settings(URL_PREFIX="", STAPEL_AUTH=_closed(
    AUTH_REGISTRATION_CLOSED_BEHAVIOR="verify",
))
class VerifyBehaviorRefusesLateTests(APITestCase):
    """The smallest diff from the pre-#86 behavior: the code still goes out,
    the refusal lands at the last step."""

    def test_code_is_sent_and_refusal_comes_at_verify(self):
        req = self.client.post(reverse("email_request"), {"email": "nobody@example.com"})
        self.assertEqual(req.status_code, status.HTTP_200_OK)
        # The 403 below is itself the proof the stored code was the mock one:
        # the refusal is reached only after the code matched.
        resp = self.client.post(
            reverse("email_verify"), {"email": "nobody@example.com", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(resp.data["localizable_error"], ERR_403_REGISTRATION_CLOSED)


class ClosedBehaviorNormalizationTests(TestCase):
    """A typo in a deploy config must fall to the CLOSED end, never open one."""

    @override_settings(STAPEL_AUTH={"AUTH_REGISTRATION_CLOSED_BEHAVIOR": "REQUEST"})
    def test_case_and_whitespace_are_forgiven(self):
        from stapel_auth.registration import closed_behavior

        self.assertEqual(closed_behavior(), "request")

    @override_settings(STAPEL_AUTH={"AUTH_REGISTRATION_CLOSED_BEHAVIOR": "loud"})
    def test_unknown_value_degrades_to_silent(self):
        from stapel_auth.registration import closed_behavior

        self.assertEqual(closed_behavior(), "silent")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Nothing changes while registration is open (the default deployment)
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(URL_PREFIX="")
class OpenRegistrationIsUnaffectedTests(APITestCase):
    def test_email_otp_still_registers(self):
        self.client.post(reverse("email_request"), {"email": "fresh@example.com"})
        resp = self.client.post(
            reverse("email_verify"), {"email": "fresh@example.com", "code": MOCK_CODE}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "REGISTERED")
        self.assertTrue(User.objects.filter(email="fresh@example.com").exists())

    @patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_oauth_still_registers(self, mock_user_data):
        mock_user_data.return_value = OAuthUserData(
            id="google-fresh-1", email="fresh-oauth@example.com",
            username="Fresh", avatar=None,
        )
        resp = self.client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "fake-token"},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email="fresh-oauth@example.com").exists())
