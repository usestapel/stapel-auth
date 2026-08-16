"""The OTP login path over the core TTL store.

Four things a user actually hits — an expired wait, wrong digits, a spent
attempt budget, and a store that cannot answer — and the one property that
made the table wrong: the code is never at rest in the clear.
"""
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_core.verification.codes import CodeOutcome

from stapel_auth.otp.services import (
    EmailVerificationService,
    PhoneVerificationService,
    email_code_store,
    phone_code_store,
)

GOOD = "0000"  # MOCK_OTP_CODE — tests run with USE_MOCK_EMAIL_OTP
BAD = "9999"


class OtpStoreServiceTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.svc = EmailVerificationService()

    # ── absence is not wrongness ─────────────────────────────────────────────

    def test_no_pending_code_reads_as_an_expired_wait(self):
        result = self.svc.verify_code("nobody@example.com", GOOD)
        assert result == {"error": "expired"}

    def test_a_cache_restart_reads_as_an_expired_wait(self):
        self.svc.send_verification_code("a@example.com")
        cache.clear()  # every pending code is gone; Redis is not durable
        assert self.svc.verify_code("a@example.com", GOOD) == {"error": "expired"}

    def test_a_spent_code_cannot_be_replayed(self):
        self.svc.send_verification_code("a@example.com")
        assert self.svc.verify_code("a@example.com", GOOD) == {"success": True}
        assert self.svc.verify_code("a@example.com", GOOD) == {"error": "expired"}

    # ── wrongness ────────────────────────────────────────────────────────────

    def test_wrong_digits_report_the_remaining_budget(self):
        self.svc.send_verification_code("a@example.com")
        result = self.svc.verify_code("a@example.com", BAD)
        assert result["error"] == "invalid_code"
        assert result["attempts_remaining"] == self.svc.max_attempts - 1

    # ── spent budget ─────────────────────────────────────────────────────────

    def test_the_budget_runs_out_into_a_block(self):
        self.svc.send_verification_code("a@example.com")
        for _ in range(self.svc.max_attempts - 1):
            assert self.svc.verify_code("a@example.com", BAD)["error"] == "invalid_code"
        spent = self.svc.verify_code("a@example.com", BAD)
        assert spent["error"] == "blocked"
        assert spent["retry_after"] == self.svc.block_duration
        # the right code does not rescue a blocked identifier
        assert self.svc.verify_code("a@example.com", GOOD)["error"] == "blocked"

    def test_a_block_outlives_the_code_it_killed(self):
        self.svc.send_verification_code("a@example.com")
        for _ in range(self.svc.max_attempts):
            self.svc.verify_code("a@example.com", BAD)
        assert email_code_store.blocked_for("a@example.com") > 0

    # ── outage ───────────────────────────────────────────────────────────────

    def test_an_unreachable_store_never_admits(self):
        self.svc.send_verification_code("a@example.com")
        with patch.object(cache, "get", side_effect=ConnectionError("redis is gone")):
            result = self.svc.verify_code("a@example.com", GOOD)
        assert result == {"error": "unavailable"}

    def test_an_unreachable_store_refuses_to_send(self):
        with patch.object(cache, "set", side_effect=ConnectionError("redis is gone")):
            assert self.svc.send_verification_code("a@example.com") is None

    # ── nothing readable is stored ───────────────────────────────────────────

    def test_the_code_is_not_at_rest_in_the_clear(self):
        self.svc.send_verification_code("a@example.com")
        record = cache.get(email_code_store._code_key("a@example.com"))
        assert GOOD not in repr(record)

    def test_email_and_phone_codes_do_not_satisfy_each_other(self):
        PhoneVerificationService().send_verification_code("+12025550100")
        assert self.svc.verify_code("+12025550100", GOOD) == {"error": "expired"}

    # ── send budget survived the table ───────────────────────────────────────

    def test_the_resend_cooldown_still_holds(self):
        assert self.svc.send_verification_code("a@example.com") is not None
        again = self.svc.send_verification_code("a@example.com")
        assert again["error"] == "rate_limit"
        assert again["retry_after"] > 0

    def test_the_hourly_cap_still_holds(self):
        for n in range(self.svc.hourly_limit):
            with patch.object(self.svc, "resend_cooldown", 0):
                assert self.svc.send_verification_code("a@example.com") is not None
        with patch.object(self.svc, "resend_cooldown", 0):
            capped = self.svc.send_verification_code("a@example.com")
        assert capped["error"] == "rate_limit"

    def test_a_blocked_identifier_is_not_sent_another_code(self):
        self.svc.send_verification_code("a@example.com")
        for _ in range(self.svc.max_attempts):
            self.svc.verify_code("a@example.com", BAD)
        with patch.object(self.svc, "resend_cooldown", 0):
            result = self.svc.send_verification_code("a@example.com")
        assert result["error"] == "blocked"


class OtpStoreHttpTests(APITestCase):
    """How the four modes read to a user at the endpoint."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def _verify(self, code):
        return self.client.post(
            reverse("email_verify"), {"email": "a@example.com", "code": code}
        )

    def test_expired_wait_invites_a_restart(self):
        response = self._verify(GOOD)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["localizable_error"] == "error.400.code_expired"
        assert "sign in again" in response.data["error"].lower()

    def test_wrong_code_says_wrong_code(self):
        EmailVerificationService().send_verification_code("a@example.com")
        response = self._verify(BAD)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["localizable_error"] == "error.400.invalid_code_attempts"

    def test_too_many_attempts_is_a_wait_not_a_verdict(self):
        svc = EmailVerificationService()
        svc.send_verification_code("a@example.com")
        for _ in range(svc.max_attempts):
            svc.verify_code("a@example.com", BAD)
        response = self._verify(GOOD)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert response.data["localizable_error"] == "error.422.blocked"

    def test_an_outage_is_a_503_not_a_rejection(self):
        EmailVerificationService().send_verification_code("a@example.com")
        with patch.object(cache, "get", side_effect=ConnectionError("redis is gone")):
            response = self._verify(GOOD)
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert (
            response.data["localizable_error"] == "error.503.verification_unavailable"
        )
        assert "could not" in response.data["error"].lower()


class OtpTableIsGoneTests(APITestCase):
    def test_the_models_no_longer_exist(self):
        import stapel_auth.models as models

        assert not hasattr(models, "PhoneVerification")
        assert not hasattr(models, "EmailVerification")

    def test_no_sweeper_remains_for_a_ttl_store(self):
        from stapel_auth.security.services import SecurityService

        assert not hasattr(SecurityService, "cleanup_expired_verifications")

    def test_erasure_still_drops_a_pending_code(self):
        from django.contrib.auth import get_user_model

        from stapel_auth.gdpr import AuthGDPRProvider

        cache.clear()
        user = get_user_model().objects.create_user(
            username="erase-me", email="erase@example.com", password="x"
        )
        EmailVerificationService().send_verification_code("erase@example.com")
        AuthGDPRProvider().delete(user.id)
        assert (
            EmailVerificationService().verify_code("erase@example.com", GOOD)
            == {"error": "expired"}
        )


@pytest.mark.parametrize(
    "outcome", [CodeOutcome.NOT_FOUND, CodeOutcome.MISMATCH, CodeOutcome.UNAVAILABLE]
)
def test_no_outcome_but_ok_is_ever_a_success(outcome):
    """A guard against the next person folding these back together."""
    from stapel_auth.otp.services import _result_for

    assert "success" not in _result_for(type("C", (), {
        "outcome": outcome, "attempts_remaining": 1, "retry_after": 1,
    })(), block_duration=600)


def test_phone_store_is_a_distinct_purpose():
    assert phone_code_store.purpose != email_code_store.purpose
