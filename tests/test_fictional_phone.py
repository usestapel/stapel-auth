"""``fictional_phone``: a runtime helper (no pytest, no Django at import) whose
numbers are all valid for stapel-auth and all inside the reserved range."""
import random
import subprocess
import sys

from stapel_auth.fictional import (
    FICTIONAL_PHONE_POOL_SIZE,
    fictional_phone,
    fictional_phone_at,
)
from stapel_auth.otp.serializers import normalize_phone
from stapel_auth.testing import unique_phone


def test_every_number_in_the_pool_is_valid_and_reserved():
    seen = set()
    for index in range(FICTIONAL_PHONE_POOL_SIZE):
        phone = fictional_phone_at(index)
        assert normalize_phone(phone) == phone
        assert phone[5:9] == "5550" and 100 <= int(phone[8:]) <= 199, phone
        seen.add(phone)
    assert len(seen) == FICTIONAL_PHONE_POOL_SIZE


def test_a_seeded_rng_reproduces_the_draw():
    first = [fictional_phone(random.Random(7)) for _ in range(3)]
    again = [fictional_phone(random.Random(7)) for _ in range(3)]
    assert first == again
    drawn = fictional_phone()
    assert normalize_phone(drawn) == drawn


def test_exported_from_the_package():
    import stapel_auth

    assert stapel_auth.fictional_phone is fictional_phone


def test_unique_phone_draws_from_the_same_pool():
    pool = {fictional_phone_at(i) for i in range(FICTIONAL_PHONE_POOL_SIZE)}
    assert {unique_phone() for _ in range(5)} <= pool


def test_importable_without_pytest_or_django_settings():
    code = (
        "import sys; sys.modules['pytest'] = None\n"
        "from stapel_auth import fictional_phone\n"
        "print(fictional_phone())\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip().startswith("+1")
