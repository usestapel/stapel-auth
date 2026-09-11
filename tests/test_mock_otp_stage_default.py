"""The posture stage owns the mock-OTP default (0.38.0).

The defect this closes, in one sentence: the mock flags were a per-service
``STAPEL_AUTH`` line, so a fleet where one service MOUNTS this module and
another only CONSUMES it had two answers to one question. On a client fleet
(2026-09-11) the auth service declared the block and mocked; the profiles
service, which runs ``PhoneVerificationService`` inside its own process for
contact verification, declared none, fell back to ``False``, and sent a real
code into an unconfigured SMS provider — ``INFO ... Verification code sent to phone``
followed by ``WARN ... Invalid code for phone, 4 attempts left``, forever.

The posture already says, once per deployment, whether this is an unadvertised
prototype. It now decides the default too.
"""
import pytest

from stapel_auth.conf import DEFAULTS, auth_settings

#: The library's documented mock code — conf.py DEFAULTS, MODULE.md's table,
#: and what the derived prototype default runs on. Read, never restated.
MOCK = DEFAULTS["MOCK_OTP_CODE"]


def _posture(settings, stage):
    from stapel_core.django.presets import public_space

    settings.STAPEL_POSTURE = public_space(stage=stage)["STAPEL_POSTURE"]


def _auth(settings, **keys):
    """Say EXACTLY what this deployment declares about the mock keys.

    Both routes have to be cleared, not just the namespace dict: the harness
    (``_codegen_settings.settings_kwargs``) sets flat ``USE_MOCK_SMS_OTP=True``
    / ``USE_MOCK_EMAIL_OTP=True`` at module scope, which is a declaration in
    its own right — leaving it in place would make every assertion below true
    for a reason that has nothing to do with the stage.
    """
    settings.STAPEL_AUTH = keys
    for flat in ("USE_MOCK_SMS_OTP", "USE_MOCK_EMAIL_OTP"):
        if hasattr(settings, flat):
            delattr(settings, flat)


class TestTheStageDecidesTheDefault:
    def test_prototype_and_unset_mocks_both_channels(self, settings):
        _posture(settings, "prototype")
        _auth(settings)

        assert auth_settings.USE_MOCK_SMS_OTP is True
        assert auth_settings.USE_MOCK_EMAIL_OTP is True

    def test_the_mock_code_is_the_libraries_documented_constant(self, settings):
        _posture(settings, "prototype")
        _auth(settings)

        assert auth_settings.MOCK_OTP_CODE == MOCK
        assert MOCK == "0000"

    def test_live_and_unset_leaves_both_channels_real(self, settings):
        _posture(settings, "live")
        _auth(settings)

        assert auth_settings.USE_MOCK_SMS_OTP is False
        assert auth_settings.USE_MOCK_EMAIL_OTP is False

    def test_no_posture_at_all_leaves_both_channels_real(self, settings):
        settings.STAPEL_POSTURE = None
        _auth(settings)

        assert auth_settings.USE_MOCK_SMS_OTP is False
        assert auth_settings.USE_MOCK_EMAIL_OTP is False

    def test_an_explicit_false_still_wins_under_prototype(self, settings):
        _posture(settings, "prototype")
        _auth(settings, USE_MOCK_SMS_OTP=False)

        assert auth_settings.USE_MOCK_SMS_OTP is False
        # ...and says nothing about the channel nobody pinned.
        assert auth_settings.USE_MOCK_EMAIL_OTP is True

    def test_a_flat_django_setting_counts_as_a_declaration(self, settings):
        # The legacy resolution route AppSettings documents, and the one
        # override_settings(USE_MOCK_SMS_OTP=...) uses across this suite.
        _posture(settings, "prototype")
        _auth(settings)
        settings.USE_MOCK_SMS_OTP = False

        assert auth_settings.declares("USE_MOCK_SMS_OTP") is True
        assert auth_settings.USE_MOCK_SMS_OTP is False

    def test_the_default_is_read_when_consumed_not_pinned_at_import(self, settings):
        """Gate #62: a setting nailed down before the preset was applied.

        The posture is spread by the settings module itself, so anything this
        package reads while that module is still executing predates it. The
        proof that nothing is pinned: the answer changes under a process that
        has already read the key.
        """
        _posture(settings, "live")
        _auth(settings)
        assert auth_settings.USE_MOCK_SMS_OTP is False

        _posture(settings, "prototype")
        assert auth_settings.USE_MOCK_SMS_OTP is True


@pytest.mark.django_db
class TestTheServiceAcceptsTheMockCodeOnAStageAlone:
    """The arm a client fleet needed: a consumer process that declares no
    ``STAPEL_AUTH`` block at all verifies a phone on the posture alone."""

    def test_phone_verification_accepts_the_mock_code(self, settings):
        _posture(settings, "prototype")
        _auth(settings)

        from stapel_auth.otp.services import PhoneVerificationService

        service = PhoneVerificationService()
        assert service.use_mock_otp is True

        phone = "+79995550142"
        assert service.send_verification_code(phone)
        result = service.verify_code(phone, MOCK)
        assert result.get("success") is True, result

    def test_a_live_stage_still_refuses_the_mock_code(self, settings):
        _posture(settings, "live")
        _auth(settings)

        from stapel_auth.otp.services import PhoneVerificationService

        service = PhoneVerificationService()
        assert service.use_mock_otp is False

    def test_the_contract_reports_the_mocked_channel(self, settings):
        _posture(settings, "prototype")
        _auth(settings)

        from stapel_auth.otp.services import issued_code_length

        # A mocked channel issues MOCK_OTP_CODE verbatim, so the width the
        # frontend builds its input from is that string's.
        assert issued_code_length("phone") == len(MOCK)
        assert issued_code_length("email") == len(MOCK)


class TestW013ReportsAnExplicitRefusal:
    def _run(self, settings):
        from stapel_auth.checks import check_mock_otp_not_declined_in_a_prototype

        return check_mock_otp_not_declined_in_a_prototype()

    def test_an_explicit_false_under_prototype_is_a_finding(self, settings):
        _posture(settings, "prototype")
        _auth(settings, USE_MOCK_SMS_OTP=False)

        findings = self._run(settings)
        assert [f.id for f in findings] == ["stapel_auth.W013"]
        assert findings[0].level < 40  # a warning: the departure is allowed
        assert "USE_MOCK_SMS_OTP" in findings[0].msg

    def test_both_pinned_off_is_reported_per_key(self, settings):
        _posture(settings, "prototype")
        _auth(settings, USE_MOCK_SMS_OTP=False, USE_MOCK_EMAIL_OTP=False)

        findings = self._run(settings)
        assert [f.id for f in findings] == ["stapel_auth.W013"] * 2
        assert "USE_MOCK_EMAIL_OTP" in findings[0].msg
        assert "USE_MOCK_SMS_OTP" in findings[1].msg

    def test_an_unset_key_is_not_a_departure(self, settings):
        _posture(settings, "prototype")
        _auth(settings)

        assert self._run(settings) == []

    def test_an_explicit_true_under_prototype_is_not_a_departure(self, settings):
        _posture(settings, "prototype")
        _auth(settings, USE_MOCK_SMS_OTP=True, USE_MOCK_EMAIL_OTP=True)

        assert self._run(settings) == []

    def test_a_live_stage_reports_nothing_here(self, settings):
        _posture(settings, "live")
        _auth(settings, USE_MOCK_SMS_OTP=False, USE_MOCK_EMAIL_OTP=False)

        assert self._run(settings) == []

    def test_no_posture_reports_nothing_here(self, settings):
        settings.STAPEL_POSTURE = None
        _auth(settings, USE_MOCK_SMS_OTP=False, USE_MOCK_EMAIL_OTP=False)

        assert self._run(settings) == []


class TestTheOtherTwoFindingsAreUnchanged:
    """E001/E004 keep their exact pre-0.38 behaviour on a live deployment."""

    def _e001(self, settings, **auth):
        settings.DEBUG = False
        _auth(settings, **auth)
        from stapel_auth.checks import check_mock_otp_disabled_in_production

        return check_mock_otp_disabled_in_production()

    def _e004(self, settings, hosts, **auth):
        settings.ALLOWED_HOSTS = hosts
        _auth(settings, **auth)
        from stapel_auth.checks import check_mock_otp_not_on_a_public_host

        return check_mock_otp_not_on_a_public_host()

    def test_explicit_true_under_live_is_still_an_error(self, settings):
        _posture(settings, "live")
        assert [f.id for f in self._e001(settings, USE_MOCK_SMS_OTP=True)] == [
            "stapel_auth.E001"
        ]
        assert [
            f.id for f in self._e004(settings, ["stand.example.com"],
                                     USE_MOCK_SMS_OTP=True)
        ] == ["stapel_auth.E004"]

    def test_the_derived_default_never_manufactures_an_error(self, settings):
        """A live/undeclared deployment cannot acquire a mock it never set, so
        the derivation can never be the thing E001/E004 report."""
        _posture(settings, "live")
        assert self._e001(settings) == []
        assert self._e004(settings, ["stand.example.com"]) == []

        settings.STAPEL_POSTURE = None
        assert self._e001(settings) == []
        assert self._e004(settings, ["stand.example.com"]) == []
