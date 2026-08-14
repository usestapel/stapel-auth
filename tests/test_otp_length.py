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
