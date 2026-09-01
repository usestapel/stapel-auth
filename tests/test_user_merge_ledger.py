"""The merge ledger — the mapping outlives the announcement.

``user.merged`` is the instruction: consumers reassign the guest's rows onto
the survivor. It is a delivery, and a delivery is not a record. A stream has
retention. A service deployed the week after a merge never saw the event. A
consumer whose handler raised for a week cannot ask what it missed. And the
guest row — the only other place in this service where the mapping existed —
is deleted in the merge's own transaction.

So ``UserMerge`` is written in that same transaction. These tests are about
three claims:

* the row exists after every merge path, including the two OAuth ones;
* it is written atomically with the emit and the delete, so it can never
  record a merge that did not happen;
* it answers the reconciliation question — including through chains, which
  is the case a one-hop lookup gets wrong.
"""
import uuid
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import MergeSource, UserMerge
from stapel_auth.otp.services import (
    EmailVerificationService,
    PhoneVerificationService,
    merge_anonymous_into,
)

User = get_user_model()

MOCK_CODE = "0000"


class LedgerUnitTests(APITestCase):
    """The write itself, without an HTTP walk."""

    def setUp(self):
        self.survivor = User.objects.create_user(
            username="survivor_unit", email="survivor@example.com",
            password="testpass123!",
        )
        self.guest = User.objects.create_user(
            username="guest_unit", email="", password="testpass123!",
        )
        self.guest.is_anonymous = True
        self.guest.save()

    def test_a_merge_writes_one_row(self):
        guest_id = self.guest.id
        merge_anonymous_into(guest_id, self.survivor, source=MergeSource.EMAIL_OTP)

        row = UserMerge.objects.get(merged_id=guest_id)
        self.assertEqual(str(row.survivor_id), str(self.survivor.id))
        self.assertEqual(row.source, MergeSource.EMAIL_OTP)
        self.assertIsNotNone(row.merged_at)

    def test_the_row_outlives_the_guest_it_names(self):
        """The point of the table: the guest row is gone, the mapping is not."""
        guest_id = self.guest.id
        merge_anonymous_into(guest_id, self.survivor, source=MergeSource.EMAIL_OTP)

        self.assertFalse(User.objects.filter(id=guest_id).exists())
        self.assertTrue(UserMerge.objects.filter(merged_id=guest_id).exists())

    def test_a_source_nobody_passed_is_recorded_as_unknown_not_guessed(self):
        merge_anonymous_into(self.guest.id, self.survivor)

        row = UserMerge.objects.get(merged_id=self.guest.id)
        self.assertEqual(row.source, MergeSource.UNKNOWN)

    def test_a_second_merge_of_the_same_guest_does_not_duplicate_the_row(self):
        """`merged_id` is unique: an id can only be absorbed once."""
        guest_id = self.guest.id
        merge_anonymous_into(guest_id, self.survivor, source=MergeSource.EMAIL_OTP)
        # A retry that somehow reached the service twice.
        merge_anonymous_into(guest_id, self.survivor, source=MergeSource.EMAIL_OTP)

        self.assertEqual(UserMerge.objects.filter(merged_id=guest_id).count(), 1)

    def test_a_failed_merge_leaves_no_ledger_row(self):
        """Atomic with the delete: no record of a merge that did not happen.

        A ledger that could disagree with reality is worse than no ledger,
        because somebody would trust it. The delete is the LAST statement in
        the transaction, so it is the one whose failure would strand a row
        that says a merge happened when the guest is still signing in.
        """
        guest_id = self.guest.id

        def _boom():
            raise RuntimeError("the delete failed")

        with mock.patch(
            "django.contrib.auth.get_user_model", side_effect=_boom
        ):
            with self.assertRaises(RuntimeError):
                merge_anonymous_into(
                    guest_id, self.survivor, source=MergeSource.EMAIL_OTP
                )

        self.assertFalse(UserMerge.objects.filter(merged_id=guest_id).exists())
        self.assertTrue(User.objects.filter(id=guest_id).exists())


class LedgerResolveTests(APITestCase):
    """The reconciliation read."""

    def test_an_id_that_was_never_merged_comes_back_unchanged(self):
        """Safe to call on every id, not only suspected ones."""
        stranger = uuid.uuid4()
        self.assertEqual(str(UserMerge.resolve(stranger)), str(stranger))

    def test_resolve_follows_one_hop(self):
        guest, survivor = uuid.uuid4(), uuid.uuid4()
        UserMerge.objects.create(merged_id=guest, survivor_id=survivor)

        self.assertEqual(str(UserMerge.resolve(guest)), str(survivor))

    def test_resolve_follows_the_whole_chain_not_one_hop(self):
        """A one-hop answer is another dead id, handed back as if it were good."""
        a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        UserMerge.objects.create(merged_id=a, survivor_id=b)
        UserMerge.objects.create(merged_id=b, survivor_id=c)

        self.assertEqual(str(UserMerge.resolve(a)), str(c))

    def test_a_cycle_stops_rather_than_spinning(self):
        a, b = uuid.uuid4(), uuid.uuid4()
        UserMerge.objects.create(merged_id=a, survivor_id=b)
        UserMerge.objects.create(merged_id=b, survivor_id=a)

        # The answer is not meaningful — a cycle is a corrupt ledger — but it
        # terminates, which is the property being asserted.
        self.assertIn(str(UserMerge.resolve(a)), {str(a), str(b)})

    def test_absorbed_by_collects_the_tree_under_a_survivor(self):
        a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        UserMerge.objects.create(merged_id=a, survivor_id=b)
        UserMerge.objects.create(merged_id=b, survivor_id=c)

        absorbed = {str(i) for i in UserMerge.absorbed_by(c)}
        self.assertEqual(absorbed, {str(a), str(b)})

    def test_absorbed_by_an_untouched_account_is_empty(self):
        self.assertEqual(UserMerge.absorbed_by(uuid.uuid4()), [])


class LedgerFunctionTests(APITestCase):
    """``auth.resolve_merged_user`` — how another service asks."""

    def _call(self, user_id):
        from stapel_auth.functions import resolve_merged_user

        return resolve_merged_user({"user_id": str(user_id)})

    def test_an_unmerged_id_answers_merged_false(self):
        stranger = uuid.uuid4()
        result = self._call(stranger)

        self.assertEqual(result["user_id"], str(stranger))
        self.assertFalse(result["merged"])
        self.assertIsNone(result["source"])

    def test_a_merged_id_answers_with_the_survivor_and_the_proof(self):
        guest, survivor = uuid.uuid4(), uuid.uuid4()
        UserMerge.objects.create(
            merged_id=guest, survivor_id=survivor,
            source=MergeSource.OAUTH_IDENTITY,
        )

        result = self._call(guest)

        self.assertEqual(result["user_id"], str(survivor))
        self.assertTrue(result["merged"])
        self.assertEqual(result["source"], MergeSource.OAUTH_IDENTITY)
        self.assertIsNotNone(result["merged_at"])

    def test_the_function_resolves_a_chain(self):
        a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        UserMerge.objects.create(merged_id=a, survivor_id=b)
        UserMerge.objects.create(merged_id=b, survivor_id=c)

        self.assertEqual(self._call(a)["user_id"], str(c))

    def test_it_is_registered_as_a_comm_function(self):
        from stapel_core.comm.registry import function_registry

        self.assertIn("auth.resolve_merged_user", function_registry._providers)


@override_settings(URL_PREFIX="")
class LedgerOverTheOtpWalkTests(APITestCase):
    """The real HTTP paths, so the source is what the call site actually passes."""

    def _mint_guest(self):
        response = APIClient().post(reverse("anonymous"), {}, format="json")
        self.assertIn(
            response.status_code,
            [status.HTTP_200_OK, status.HTTP_201_CREATED],
            response.content,
        )
        client = APIClient()
        client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {response.data['tokens']['access']}"
        )
        return response.data["user"]["id"], client

    def test_the_email_merge_is_recorded_as_email_otp(self):
        taken = User.objects.create_user(
            username="ledger_email_holder", email="ledger-email@example.com",
            password="testpass123!",
        )
        guest_id, client = self._mint_guest()
        EmailVerificationService().send_verification_code("ledger-email@example.com")

        with self.captureOnCommitCallbacks(execute=True):
            client.post(
                reverse("email_verify"),
                {"email": "ledger-email@example.com", "code": MOCK_CODE},
            )

        row = UserMerge.objects.get(merged_id=guest_id)
        self.assertEqual(str(row.survivor_id), str(taken.id))
        self.assertEqual(row.source, MergeSource.EMAIL_OTP)

    def test_the_phone_merge_is_recorded_as_phone_otp(self):
        taken = User.objects.create_user(
            username="ledger_phone_holder",
            phone="+12345670077",
            auth_type="phone",
        )
        guest_id, client = self._mint_guest()
        PhoneVerificationService().send_verification_code("+12345670077")

        with self.captureOnCommitCallbacks(execute=True):
            response = client.post(
                reverse("phone_verify"),
                {"phone": "+12345670077", "code": MOCK_CODE},
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)

        row = UserMerge.objects.filter(merged_id=guest_id).first()
        self.assertIsNotNone(row, "the phone merge wrote no ledger row")
        self.assertEqual(str(row.survivor_id), str(taken.id))
        self.assertEqual(row.source, MergeSource.PHONE_OTP)


@override_settings(URL_PREFIX="")
class LedgerOverTheOauthWalkTests(APITestCase):
    """The two OAuth merges, which the event's ``reason`` cannot tell apart.

    Both emit ``reason="anonymous_promotion"``. They are not the same claim:
    a ``(provider, oauth_id)`` match is the provider saying "this is the same
    account you saw before", while an email match is the provider asserting
    an address is verified — a much weaker statement, and the one an attacker
    would attack. The ledger is where that distinction is kept.
    """

    def _guest_client(self):
        from stapel_core.django.jwt.provider import jwt_provider

        anon = User.create_anonymous_user()
        access, _ = jwt_provider.create_tokens(anon)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return anon, client

    @mock.patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_a_provider_identity_match_is_recorded_as_oauth_identity(
        self, mock_get_user_data
    ):
        from stapel_auth.oauth_providers import OAuthUserData

        existing = User.objects.create_user(
            username="ledger_oauth_identity",
            email="ledger-oauth-id@example.com",
            password="x",
        )
        existing.oauth_provider = "google"
        existing.oauth_id = "ledger-uid-1"
        existing.save()
        anon, client = self._guest_client()
        mock_get_user_data.return_value = OAuthUserData(
            id="ledger-uid-1",
            email="ledger-oauth-id@example.com",
            username="ledger_oauth_identity",
            avatar=None,
            email_verified=True,
        )

        with self.captureOnCommitCallbacks(execute=True):
            response = client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "tok"},
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MERGED")
        row = UserMerge.objects.get(merged_id=anon.id)
        self.assertEqual(str(row.survivor_id), str(existing.id))
        self.assertEqual(row.source, MergeSource.OAUTH_IDENTITY)

    @mock.patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_a_verified_email_match_is_recorded_as_oauth_email(
        self, mock_get_user_data
    ):
        from stapel_auth.oauth_providers import OAuthUserData

        existing = User.objects.create_user(
            username="ledger_oauth_email",
            email="ledger-oauth-email@example.com",
            password="x",
        )
        anon, client = self._guest_client()
        mock_get_user_data.return_value = OAuthUserData(
            id="ledger-uid-2",
            email="ledger-oauth-email@example.com",
            username="ledger_oauth_email",
            avatar=None,
            email_verified=True,
        )

        with self.captureOnCommitCallbacks(execute=True):
            response = client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "tok"},
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "MERGED")
        row = UserMerge.objects.get(merged_id=anon.id)
        self.assertEqual(str(row.survivor_id), str(existing.id))
        self.assertEqual(row.source, MergeSource.OAUTH_EMAIL)

    @mock.patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_a_refused_unverified_collision_writes_no_row(
        self, mock_get_user_data
    ):
        """No merge happened, so the ledger must not claim one did."""
        from stapel_auth.oauth_providers import OAuthUserData

        User.objects.create_user(
            username="ledger_oauth_unverified",
            email="ledger-oauth-unverified@example.com",
            password="x",
        )
        anon, client = self._guest_client()
        mock_get_user_data.return_value = OAuthUserData(
            id="ledger-uid-3",
            email="ledger-oauth-unverified@example.com",
            username="ledger_oauth_unverified",
            avatar=None,
            email_verified=False,
        )

        with self.captureOnCommitCallbacks(execute=True):
            client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "tok"},
            )

        self.assertFalse(UserMerge.objects.filter(merged_id=anon.id).exists())
        self.assertTrue(User.objects.filter(pk=anon.pk).exists())

    @mock.patch("stapel_auth.oauth.services.OAuthService.get_user_data")
    def test_a_signed_in_user_is_not_a_guest_and_writes_no_row(
        self, mock_get_user_data
    ):
        from stapel_auth.oauth_providers import OAuthUserData

        existing = User.objects.create_user(
            username="ledger_oauth_signed_in",
            email="ledger-oauth-signedin@example.com",
            password="x",
        )
        mock_get_user_data.return_value = OAuthUserData(
            id="ledger-uid-4",
            email="ledger-oauth-signedin@example.com",
            username="ledger_oauth_signed_in",
            avatar=None,
            email_verified=True,
        )

        with self.captureOnCommitCallbacks(execute=True):
            APIClient().post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "tok"},
            )

        self.assertFalse(
            UserMerge.objects.filter(survivor_id=existing.id).exists()
        )
