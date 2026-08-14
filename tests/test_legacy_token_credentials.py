"""Every password entry point must verify the password (audit AUTH-01, P0).

The defect was a seam, not a line of code. ``stapel-auth``'s legacy
``POST /token/`` calls ``django.contrib.auth.authenticate()``, and the
deployment wired ``stapel_core.django.jwt.session.EmailAuthBackend`` into
``AUTHENTICATION_BACKENDS`` — a backend that resolved a user by email and
returned it *without comparing a secret*. Any nonempty password logged in
as any known email, staff included. Neither repo's tests saw it: core had
no caller, and this suite's settings never wired the backend, so the one
configuration that was actually deployed was the one nobody exercised.

That is why these tests wire the real backend explicitly. They are a
cross-repo gate: they fail against a ``stapel-core`` whose backend does not
call ``check_password``, which is exactly the regression to catch.

``_ALIASES`` is the enumeration — every route that turns a password into a
session. A new one added without an entry here is a new place for the same
defect to live.
"""
import uuid

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.models import UserSession

User = get_user_model()

_REAL_PW = "the-real-password-8"
_WRONG_PW = "any-nonempty-string"

#: The email-keyed backend the audited deployment actually runs, in front of
#: Django's own — the configuration under test, not a convenient one.
_BACKENDS = [
    "stapel_core.django.jwt.session.EmailAuthBackend",
    "django.contrib.auth.backends.ModelBackend",
]


def _user(**kw):
    d = dict(
        email=f"legacy-{uuid.uuid4().hex[:10]}@example.com",
        username=f"legacy_{uuid.uuid4().hex[:10]}",
        password=_REAL_PW,
        is_email_verified=True,
        auth_type="email",
    )
    d.update(kw)
    return User.objects.create_user(**d)


@override_settings(
    URL_PREFIX="",
    AUTHENTICATION_BACKENDS=_BACKENDS,
    # The legacy alias needs its own switch since 0.21 (see
    # tests/test_legacy_token_gate.py) — a suite about credential
    # verification opens the door it verifies.
    STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True, "AUTH_LEGACY_TOKEN_LOGIN": True},
)
class PasswordAliasesRejectAWrongPasswordTests(APITestCase):
    """Wrong password, every alias, by email and by username."""

    def _aliases(self, user, password):
        """``(label, response)`` for every route that trades a password."""
        return [
            (
                "legacy /token/ by email",
                self.client.post(
                    reverse("token_obtain_pair"),
                    {"email": user.email, "password": password},
                    format="json",
                ),
            ),
            (
                "legacy /token/ by username",
                self.client.post(
                    reverse("token_obtain_pair"),
                    {"username": user.username, "password": password},
                    format="json",
                ),
            ),
            (
                "/password/login/ by email",
                self.client.post(
                    reverse("password_login"),
                    {"login": user.email, "password": password},
                    format="json",
                ),
            ),
            (
                "/password/login/ by username",
                self.client.post(
                    reverse("password_login"),
                    {"login": user.username, "password": password},
                    format="json",
                ),
            ),
        ]

    def test_no_alias_accepts_a_wrong_password(self):
        for label, resp in self._aliases(_user(), _WRONG_PW):
            with self.subTest(alias=label):
                self.assertEqual(resp.status_code, 401, label)
                self.assertNotIn("access", resp.data)
                self.assertNotIn("tokens", resp.data)
                self.assertEqual(resp.cookies, {}, "a refusal set a cookie")

    def test_a_refused_login_leaves_no_session_row(self):
        user = _user()
        for label, _ in self._aliases(user, _WRONG_PW):
            with self.subTest(alias=label):
                self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_an_empty_password_is_not_a_credential(self):
        user = _user()
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"email": user.email, "password": ""},
            format="json",
        )
        self.assertIn(resp.status_code, (400, 401))
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_a_deactivated_account_cannot_log_in_with_the_right_password(self):
        user = _user(is_active=False)
        for label, resp in self._aliases(user, _REAL_PW):
            with self.subTest(alias=label):
                self.assertEqual(resp.status_code, 401, label)
                self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_the_right_password_still_logs_in_and_is_tracked(self):
        """The other half of the gate: the fix must not break login.

        One tracked ``UserSession`` per alias is the AUTH-01/AUTH-02/AUTH-04
        overlap — the legacy endpoint used to mint around the session table,
        and an untracked session is one that cannot be listed or revoked.
        """
        user = _user()
        resp = self.client.post(
            reverse("token_obtain_pair"),
            {"email": user.email, "password": _REAL_PW},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["access"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 1)

        resp = self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _REAL_PW},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(UserSession.objects.filter(user=user).count(), 2)


@override_settings(URL_PREFIX="", AUTHENTICATION_BACKENDS=_BACKENDS)
class BackendContractTests(APITestCase):
    """The seam itself, asserted directly on the backend.

    ``authenticate()`` is the interface every caller in the process trusts;
    a backend that resolves a principal without a secret is a bypass for all
    of them, not only for the endpoint that happened to expose it here.
    """

    def test_authenticate_denies_a_wrong_password_for_a_known_email(self):
        from django.contrib.auth import authenticate

        user = _user()
        self.assertIsNone(authenticate(None, username=user.email, password=_WRONG_PW))
        self.assertIsNone(authenticate(None, username=user.email, password=""))
        self.assertIsNone(authenticate(None, username=user.email, password=None))
        self.assertEqual(
            authenticate(None, username=user.email, password=_REAL_PW).pk, user.pk
        )

    def test_the_deployed_backend_stack_passes_the_boot_check(self):
        """stapel-core's boot check, run against the wiring under test.

        Wiring and backend live in different repos, which is how the bypass
        survived review. The check refuses to start when a backend overrides
        ``authenticate()`` without declaring ``verifies_credentials = True``,
        so asserting it here is asserting that this deployment shape is one
        the fleet gate accepts — not merely that today's class happens to be
        correct.
        """
        from stapel_core.django.auth_backend_checks import (
            check_authentication_backends,
        )

        self.assertEqual([e.msg for e in check_authentication_backends()], [])

    def test_the_email_backend_declares_that_it_verifies_credentials(self):
        from stapel_core.django.jwt.session import EmailAuthBackend

        self.assertIs(EmailAuthBackend.verifies_credentials, True)
