"""Budgets hold under concurrency, and SMS spend has a ceiling.

Concurrency is simulated deterministically with *stale reads*: every reader
sees the value as it was before any of them wrote — exactly what N parallel
requests see when a counter is ``get`` then ``set``. A read-modify-write
counter passes every one of them; an atomic one (``cache.add`` +
``cache.incr``) does not depend on the read at all.
"""
import copy
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from stapel_auth.otp.services import EmailVerificationService, PhoneVerificationService
from stapel_auth.security.services import LockoutService

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _fresh():
    cache.clear()
    from stapel_auth.conf import auth_settings

    auth_settings.reload()
    yield
    cache.clear()
    auth_settings.reload()


def _stale_reads(prefix):
    """cache.get answers 'nothing written yet' for keys starting with *prefix*."""
    real_get = cache.get

    def stale(key, default=None, *a, **kw):
        if str(key).startswith(prefix):
            return default
        return real_get(key, default, *a, **kw)

    return patch.object(cache, "get", side_effect=stale)


def test_lockout_counter_does_not_lose_parallel_failures():
    with _stale_reads("lockout_attempts:"):
        counts = [LockoutService.record_failure("victim@example.com") for _ in range(6)]
    assert counts == [1, 2, 3, 4, 5, 6]


def test_one_code_survives_at_most_max_attempts_guesses_in_a_burst():
    """Every parallel guess reads the code entry before any of them bumps its
    attempt count; without the atomic guard all of them were checked."""
    svc = EmailVerificationService()
    with patch.object(svc, "generate_code", return_value="135790"):
        assert svc.send_verification_code("burst@example.com", deliver=False)
    record_key = svc.store._code_key("burst@example.com")
    real_get = svc.store._get
    pristine = real_get(record_key)
    assert pristine and pristine["attempts"] == 0

    def stale(key):
        # A fresh copy per reader, as a cache round-trip would hand out.
        return copy.deepcopy(pristine) if key == record_key else real_get(key)

    with patch.object(svc.store, "_get", side_effect=stale):
        results = [svc.verify_code("burst@example.com", "000000") for _ in range(20)]
        checked = [r for r in results if r.get("error") == "invalid_code"]
        assert len(checked) <= svc.max_attempts
        assert results[-1]["error"] == "blocked"
        # The real code is refused too: the burst spent the code, not just tries.
        assert svc.verify_code("burst@example.com", "135790").get("error") == "blocked"


def test_two_sends_that_both_passed_the_cooldown_read_deliver_once():
    svc = PhoneVerificationService()
    svc.use_mock_otp = False
    with patch.object(svc.store, "send_wait", return_value=0), patch.object(
        PhoneVerificationService, "_deliver", return_value=True
    ) as deliver:
        first = svc.send_verification_code("+12025550101")
        second = svc.send_verification_code("+12025550101")
    assert first and not isinstance(first, dict)
    assert second == {"error": "rate_limit", "retry_after": svc.resend_cooldown}
    assert deliver.call_count == 1


_SMS = {
    "USE_MOCK_SMS_OTP": False,
    "OTP_RESEND_COOLDOWN": 0,
    "OTP_RATE_LIMIT_PER_HOUR": 0,
    "SMS_BUDGET_PER_IP_PER_HOUR": 2,
    "SMS_BUDGET_GLOBAL_PER_HOUR": 3,
}


def _request_codes(client, phones, ip):
    return [
        client.post(reverse("phone_request"), {"phone": p}, REMOTE_ADDR=ip)
        for p in phones
    ]


@override_settings(STAPEL_AUTH=_SMS)
def test_sms_budget_per_address_then_global_with_one_answer_for_all():
    from stapel_auth.conf import auth_settings

    auth_settings.reload()
    client = APIClient()
    with patch.object(PhoneVerificationService, "_deliver", return_value=True) as deliver:
        first = _request_codes(
            client, ["+12025550111", "+12025550112", "+12025550113"], "203.0.113.7"
        )
        assert deliver.call_count == 2  # the third is over this address's budget
        second = _request_codes(
            client, ["+12025550114", "+12025550115"], "198.51.100.9"
        )
        assert deliver.call_count == 3  # the global budget caps the rest
    answers = {(r.status_code, r.data["message"]) for r in first + second}
    # A pumper cannot tell a sent code from a withheld one.
    assert answers == {(200, "Verification code sent successfully")}
