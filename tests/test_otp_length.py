"""OTP length: configurable generation, 8-char storage cap, 6-digit mock."""
import pytest

from stapel_auth.checks import check_otp_length_within_cap
from stapel_auth.otp.constants import OTP_CODE_LENGTH


def _sa(**over):
    from django.conf import settings
    return {**getattr(settings, "STAPEL_AUTH", {}), **over}


def test_storage_cap_is_eight():
    assert OTP_CODE_LENGTH == 8


def test_generated_length_follows_setting(settings):
    settings.STAPEL_AUTH = _sa(OTP_LENGTH=6, USE_MOCK_EMAIL_OTP=False)
    from stapel_auth.otp.services import EmailVerificationService
    code = EmailVerificationService().generate_code()
    assert len(code) == 6 and code.isdigit()


def test_generated_length_default_is_six(settings):
    """The shipped default, not merely a supported value.

    It was 4 — a 10^4 space, narrowed but not enlarged by OTP_MAX_ATTEMPTS
    and OTP_RATE_LIMIT_PER_HOUR. 6 is the industry default.
    """
    settings.STAPEL_AUTH = _sa(USE_MOCK_EMAIL_OTP=False)
    from stapel_auth.conf import auth_settings
    from stapel_auth.otp.services import EmailVerificationService
    assert int(auth_settings.OTP_LENGTH) == 6
    assert len(EmailVerificationService().generate_code()) == 6


def test_a_deployment_can_still_choose_a_shorter_code(settings):
    settings.STAPEL_AUTH = _sa(OTP_LENGTH=4, USE_MOCK_EMAIL_OTP=False)
    from stapel_auth.otp.services import EmailVerificationService
    assert len(EmailVerificationService().generate_code()) == 4


@pytest.mark.django_db
def test_six_digit_mock_code_round_trips(settings):
    settings.STAPEL_AUTH = _sa(USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="147935")
    from stapel_auth.otp.services import EmailVerificationService
    svc = EmailVerificationService()
    assert svc.generate_code() == "147935"
    email = "six@example.com"
    svc.send_verification_code(email)
    assert svc.verify_code(email, "147935")


def test_check_flags_over_cap_length(settings):
    settings.STAPEL_AUTH = _sa(OTP_LENGTH=9)
    errs = check_otp_length_within_cap()
    assert any(e.id == "stapel_auth.E002" for e in errs)


def test_check_flags_over_cap_mock(settings):
    settings.STAPEL_AUTH = _sa(MOCK_OTP_CODE="123456789")
    errs = check_otp_length_within_cap()
    assert any(e.id == "stapel_auth.E002" for e in errs)


def test_check_clean_for_six(settings):
    settings.STAPEL_AUTH = _sa(OTP_LENGTH=6, MOCK_OTP_CODE="147935")
    assert check_otp_length_within_cap() == []


# ---------------------------------------------------------------------------
# One source of truth: what is ISSUED is what the contract REPORTS.
#
# The class of defect this closes: generation read MOCK_OTP_CODE while the
# capabilities contract read OTP_LENGTH, so a stand with mock OTP on ('0000')
# advertised six boxes for a four-digit code and login could not be completed
# at all. Both paths now go through otp.services.issued_code_length().
# ---------------------------------------------------------------------------


def _capabilities():
    from stapel_auth.oauth.services import AuthCapabilitiesService
    return AuthCapabilitiesService.get_capabilities()


def test_contract_reports_the_mock_width_when_mock_is_on(settings):
    """The shape that broke a live stand: MOCK_OTP_CODE='0000' -> four
    boxes, not six."""
    settings.STAPEL_AUTH = _sa(USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=True)
    from stapel_auth.conf import auth_settings
    from stapel_auth.otp.services import EmailVerificationService

    assert auth_settings.MOCK_OTP_CODE == "0000"  # the shipped default
    caps = _capabilities()
    assert caps.otp.email_code_length == 4
    assert caps.otp.phone_code_length == 4
    # ... and it is the width actually issued.
    assert len(EmailVerificationService().generate_code()) == 4


def test_contract_reports_otp_length_when_mock_is_off(settings):
    settings.STAPEL_AUTH = _sa(
        USE_MOCK_EMAIL_OTP=False, USE_MOCK_SMS_OTP=False, OTP_LENGTH=6
    )
    caps = _capabilities()
    assert caps.otp.email_code_length == 6
    assert caps.otp.phone_code_length == 6


def test_contract_is_per_channel(settings):
    """A mixed stand — mock email, real SMS — reports each channel's truth."""
    settings.STAPEL_AUTH = _sa(
        USE_MOCK_EMAIL_OTP=True, USE_MOCK_SMS_OTP=False,
        MOCK_OTP_CODE="0000", OTP_LENGTH=6,
    )
    from stapel_auth.otp.services import (
        EmailVerificationService,
        PhoneVerificationService,
    )

    caps = _capabilities()
    assert caps.otp.email_code_length == 4
    assert caps.otp.phone_code_length == 6
    assert len(EmailVerificationService().generate_code()) == 4
    assert len(PhoneVerificationService().generate_code()) == 6


def test_issued_code_length_agrees_with_generation_across_the_matrix(settings):
    """The property, not a sample: for every mock/length combination the
    contract number IS the length of the code the service hands out."""
    from stapel_auth.otp.services import (
        EmailVerificationService,
        PhoneVerificationService,
        issued_code_length,
    )

    for mock_on in (True, False):
        for mock_code in ("0000", "147935", "12345678"):
            for length in (4, 6, 8):
                settings.STAPEL_AUTH = _sa(
                    USE_MOCK_EMAIL_OTP=mock_on, USE_MOCK_SMS_OTP=mock_on,
                    MOCK_OTP_CODE=mock_code, OTP_LENGTH=length,
                )
                caps = _capabilities()
                for channel, service in (
                    ("email", EmailVerificationService),
                    ("phone", PhoneVerificationService),
                ):
                    reported = getattr(caps.otp, f"{channel}_code_length")
                    assert reported == issued_code_length(channel)
                    assert len(service().generate_code()) == reported
                    # ... and never over the storage/wire cap.
                    assert reported <= OTP_CODE_LENGTH


def test_force_real_ignores_the_mock_width(settings):
    """The admin escape hatch still gets a real OTP_LENGTH code — the contract
    describes what an ORDINARY caller receives, so it stays at the mock width."""
    settings.STAPEL_AUTH = _sa(
        USE_MOCK_EMAIL_OTP=True, MOCK_OTP_CODE="0000", OTP_LENGTH=6
    )
    from stapel_auth.otp.services import EmailVerificationService, issued_code_length

    assert len(EmailVerificationService().generate_code(force_real=True)) == 6
    assert issued_code_length("email", force_real=True) == 6
    assert issued_code_length("email") == 4


def test_serializer_cap_still_bounds_the_widest_contract(settings):
    """OTP_LENGTH=8 (the cap) is reported and accepted by the request
    serializer — the contract may reach the cap, never exceed it."""
    settings.STAPEL_AUTH = _sa(USE_MOCK_EMAIL_OTP=False, OTP_LENGTH=8)
    from stapel_auth.otp.serializers import EmailAuthVerifySerializer

    caps = _capabilities()
    assert caps.otp.email_code_length == OTP_CODE_LENGTH == 8
    assert check_otp_length_within_cap() == []
    ser = EmailAuthVerifySerializer(data={"email": "cap@example.com", "code": "8" * 8})
    assert ser.is_valid(), ser.errors
    too_long = EmailAuthVerifySerializer(
        data={"email": "cap@example.com", "code": "9" * 9}
    )
    assert not too_long.is_valid()
