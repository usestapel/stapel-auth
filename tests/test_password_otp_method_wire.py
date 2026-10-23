"""The password-OTP ``method`` enum carries wire values under a pinned name."""

import json
from pathlib import Path

from stapel_auth.password.serializers import (
    PasswordOtpRequestSerializer,
    PasswordOtpVerifySerializer,
)

SCHEMA = Path(__file__).resolve().parent.parent / "docs" / "schema.json"


def test_choices_are_the_wire_values():
    for serializer in (PasswordOtpRequestSerializer, PasswordOtpVerifySerializer):
        assert list(serializer().fields["method"].choices) == ["email", "phone"]


def test_committed_schema_names_and_values_the_enum():
    components = json.loads(SCHEMA.read_text())["components"]["schemas"]
    assert components["PasswordOtpMethodEnum"]["enum"] == ["email", "phone"]
    assert not [name for name in components if name.startswith("Method") and name.endswith("Enum")]
