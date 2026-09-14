"""What `/email/verify/` and `/phone/verify/` answer to wrong codes — and the
docs that have to say the same thing.

Two limits guard the verify endpoints, and until 0.39.2 the consumer docs
listed both of their error codes side by side for "too many wrong codes", as
if either might come back. A client reading that has no rule for which to
render, and production settled it the way it always settles ambiguity: it
answered 423, while the module's own contract did not even declare 423 on the
operation.

The two limits are different mechanisms:

* the code's OWN attempt budget (`OTP_MAX_ATTEMPTS`, default 5), stored inside
  the code entry — spending it destroys the code and blocks the identifier for
  `OTP_BLOCK_DURATION`: **422 error.422.blocked**;
* the CROSS-code failure counter (`LockoutService`, rolling hour, tiers at
  5/10/20 → 15 min / 1 h / 24 h): **423 error.423.account_locked**.

Which one a caller meets is decided by how the guesses were spread, not by how
many there were — the point the docs were missing. Emptying one code's budget
meets 422, because the counter only advances on guesses that were actually
checked and so stops one short of its first tier; spreading the same number of
guesses over re-requested codes meets 423.

The behavioural half of this file pins that. The documentary half pins that the
committed contract says it, so the next consumer doc can be written off the
schema instead of off production.
"""
import json
import uuid
from pathlib import Path

import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

REPO = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.django_db


# ─────────────────────────────────────────────────────────────────────────────
# Behaviour
# ─────────────────────────────────────────────────────────────────────────────


class TestOneCodesBudgetEndsIn422:
    def test_email(self):
        client = APIClient()
        email = f"ladder_{uuid.uuid4().hex[:8]}@example.com"
        assert client.post(reverse("email_request"), {"email": email}).status_code == 200

        def verify(code):
            return client.post(
                reverse("email_verify"), {"email": email, "code": code}
            )

        for i in range(4):
            resp = verify("9999")
            assert resp.status_code == 400, (i, resp.content)
            assert resp.data["localizable_error"] == "error.400.invalid_code_attempts"
            assert resp.data["params"]["attempts_remaining"] == 4 - i

        resp = verify("9999")
        assert resp.status_code == 422, resp.content
        assert resp.data["localizable_error"] == "error.422.blocked"

        # The block outlives the code: the correct code is refused too.
        assert verify("0000").status_code == 422

        # Asking for a fresh code is refused as well — but the send side
        # checks the 30-second resend cooldown BEFORE the block, so inside
        # that window a blocked identifier is told 429, not 422. Both are
        # true and neither is the whole story, which is why the docs now say
        # which one comes back when.
        resp = client.post(reverse("email_request"), {"email": email})
        assert resp.status_code == 429, resp.content
        assert resp.data["localizable_error"] == "error.429.rate_limit"

        with override_settings(STAPEL_AUTH={"OTP_RESEND_COOLDOWN": 0}):
            resp = client.post(reverse("email_request"), {"email": email})
        assert resp.status_code == 422, resp.content
        assert resp.data["localizable_error"] == "error.422.blocked"

    def test_phone(self):
        client = APIClient()
        phone = "+12025550177"
        assert client.post(reverse("phone_request"), {"phone": phone}).status_code == 200

        def verify(code):
            return client.post(
                reverse("phone_verify"), {"phone": phone, "code": code}
            )

        for _ in range(4):
            assert verify("9999").status_code == 400
        resp = verify("9999")
        assert resp.status_code == 422, resp.content
        assert resp.data["localizable_error"] == "error.422.blocked"


class TestGuessesSpreadOverReRequestedCodesEndIn423:
    """The 423 tier, reached the only way a caller can reach it.

    Four guesses against the first code leave it alive (the budget is 5) and
    the cross-code counter at four. A fresh code resets the budget but not the
    counter, so the fifth guess — the first one the counter has ever seen cross
    a tier — locks the identifier.
    """

    @override_settings(STAPEL_AUTH={"OTP_RESEND_COOLDOWN": 0})
    def test_email(self):
        client = APIClient()
        email = f"ladder_{uuid.uuid4().hex[:8]}@example.com"
        assert client.post(reverse("email_request"), {"email": email}).status_code == 200

        def verify(code):
            return client.post(
                reverse("email_verify"), {"email": email, "code": code}
            )

        for _ in range(4):
            assert verify("9999").status_code == 400

        # A second code: a fresh budget, the same counter.
        assert client.post(reverse("email_request"), {"email": email}).status_code == 200

        resp = verify("9999")
        assert resp.status_code == 423, resp.content
        assert resp.data["localizable_error"] == "error.423.account_locked"
        assert resp.data["params"]["retry_after_minutes"] == 15

        # Checked before the code is: even the right code gets 423 now.
        assert verify("0000").status_code == 423


# ─────────────────────────────────────────────────────────────────────────────
# Documentation — the committed contract must carry what the views emit
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def schema():
    path = REPO / "docs" / "schema.json"
    if not path.exists():  # installed as a wheel — docs/ is not shipped
        pytest.skip("docs/schema.json not present")
    return json.loads(path.read_text())


#: The canonical mount the contract is emitted at (_codegen.py / codegen_urls.py).
_PREFIX = "/auth/api/v1"


def _operation(schema, path, method="post"):
    # Exact, not endswith: `/phone/verify/` is also the tail of
    # `/password/reset/phone/verify/`, and a suffix match quietly asserted
    # against the wrong operation.
    try:
        return schema["paths"][_PREFIX + path][method]
    except KeyError:
        raise AssertionError(f"{_PREFIX + path} [{method}] not in the emitted schema")


@pytest.mark.parametrize("path", ["/email/verify/", "/phone/verify/"])
def test_verify_declares_every_lockout_status_it_can_emit(schema, path):
    declared = set(_operation(schema, path)["responses"])
    for code in ("400", "422", "423", "503"):
        assert code in declared, (
            f"{path} can emit {code} but the contract does not declare it — "
            "a consumer generating error handling off this schema gets no "
            f"branch for it. Declared: {sorted(declared)}"
        )


@pytest.mark.parametrize("path", ["/email/verify/", "/phone/verify/"])
def test_verify_description_separates_422_from_423(schema, path):
    description = _operation(schema, path)["description"]
    assert "error.422.blocked" in description
    assert "error.423.account_locked" in description
    # The distinguishing rule, not just the two codes next to each other.
    assert "OTP_MAX_ATTEMPTS" in description
    assert "RE-REQUESTED" in description


@pytest.mark.parametrize("path", ["/email/request/", "/phone/request/"])
def test_request_declares_the_rate_limit_it_emits(schema, path):
    declared = set(_operation(schema, path)["responses"])
    assert "429" in declared, (
        f"{path} answers 429 error.429.rate_limit on the resend cooldown; "
        f"declared: {sorted(declared)}"
    )


def test_module_md_states_the_rule():
    module_md = REPO / "MODULE.md"
    if not module_md.exists():
        pytest.skip("MODULE.md not present")
    text = module_md.read_text()
    assert "error.422.blocked" in text
    assert "error.423.account_locked" in text
