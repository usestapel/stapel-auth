"""The hourly limits in conf.py are consumed, not decorative.

``OTP_RATE_LIMIT_PER_HOUR`` and ``MAGIC_LINK_RATE_LIMIT_PER_HOUR`` shipped in
``conf.py``, are documented as caps, and appeared nowhere else in the package
— the OTP path threw only ``OTP_RESEND_COOLDOWN`` (a gap between consecutive
sends: 120 codes an hour to one address at the default 30s) at the problem,
and the magic-link path used a hardcoded ``RATE_LIMIT = 3`` that ignored the
setting entirely. A knob that changes nothing is worse than a missing one:
the deployment believes it has a cap.

These tests set the settings to values a hardcoded implementation cannot
produce, which is the only way to tell a wired knob from a decorative one.
"""
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from stapel_auth.models import EmailVerification, PhoneVerification

User = get_user_model()


def _sa(**over):
    return {"USE_MOCK_EMAIL_OTP": False, "USE_MOCK_SMS_OTP": False, **over}


@override_settings(STAPEL_AUTH=_sa(OTP_RATE_LIMIT_PER_HOUR=2, OTP_RESEND_COOLDOWN=0))
class OtpHourlyLimitTests(TestCase):
    """Cooldown 0 isolates the hourly cap: only it can stop the third send."""

    def test_email_sends_are_capped_per_hour(self):
        from stapel_auth.otp.services import EmailVerificationService

        svc = EmailVerificationService()
        email = f"cap-{uuid.uuid4().hex[:8]}@example.com"
        self.assertNotIsInstance(svc.send_verification_code(email), dict)
        self.assertNotIsInstance(svc.send_verification_code(email), dict)
        third = svc.send_verification_code(email)
        self.assertEqual(third.get("error"), "rate_limit")
        self.assertGreater(third.get("retry_after"), 0)
        self.assertEqual(EmailVerification.objects.filter(email=email).count(), 2)

    def test_phone_sends_are_capped_per_hour(self):
        from stapel_auth.otp.services import PhoneVerificationService

        svc = PhoneVerificationService()
        phone = "+12025551313"
        self.assertNotIsInstance(svc.send_verification_code(phone), dict)
        self.assertNotIsInstance(svc.send_verification_code(phone), dict)
        third = svc.send_verification_code(phone)
        self.assertEqual(third.get("error"), "rate_limit")
        self.assertEqual(PhoneVerification.objects.filter(phone=phone).count(), 2)

    def test_the_budget_is_per_identifier(self):
        from stapel_auth.otp.services import EmailVerificationService

        svc = EmailVerificationService()
        first = f"a-{uuid.uuid4().hex[:8]}@example.com"
        second = f"b-{uuid.uuid4().hex[:8]}@example.com"
        svc.send_verification_code(first)
        svc.send_verification_code(first)
        self.assertEqual(svc.send_verification_code(first).get("error"), "rate_limit")
        self.assertNotIsInstance(svc.send_verification_code(second), dict)

    def test_sends_older_than_the_window_do_not_count(self):
        from stapel_auth.otp.services import EmailVerificationService

        svc = EmailVerificationService()
        email = f"old-{uuid.uuid4().hex[:8]}@example.com"
        for _ in range(2):
            svc.send_verification_code(email)
        EmailVerification.objects.filter(email=email).update(
            created_at=timezone.now() - timezone.timedelta(hours=2)
        )
        self.assertNotIsInstance(svc.send_verification_code(email), dict)

    @override_settings(
        STAPEL_AUTH=_sa(OTP_RATE_LIMIT_PER_HOUR=0, OTP_RESEND_COOLDOWN=0)
    )
    def test_zero_disables_the_hourly_cap(self):
        from stapel_auth.otp.services import EmailVerificationService

        svc = EmailVerificationService()
        email = f"unlimited-{uuid.uuid4().hex[:8]}@example.com"
        for _ in range(5):
            self.assertNotIsInstance(svc.send_verification_code(email), dict)


class MagicLinkLimitIsConfigurableTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            email=f"ml-{uuid.uuid4().hex[:8]}@example.com",
            username=f"ml_{uuid.uuid4().hex[:8]}",
            password="x",
            is_email_verified=True,
        )

    @override_settings(STAPEL_AUTH={"MAGIC_LINK_RATE_LIMIT_PER_HOUR": 1})
    def test_the_setting_drives_the_cap_not_the_hardcoded_three(self):
        from stapel_auth.magic_link.services import MagicLinkService

        self.assertIsNotNone(MagicLinkService.create(self.user))
        self.assertIsNone(
            MagicLinkService.create(self.user),
            "the second link was minted — the hardcoded RATE_LIMIT=3 is still in charge",
        )

    @override_settings(STAPEL_AUTH={"MAGIC_LINK_RATE_LIMIT_PER_HOUR": 5})
    def test_raising_the_setting_actually_raises_the_cap(self):
        from stapel_auth.magic_link.services import MagicLinkService

        for _ in range(5):
            self.assertIsNotNone(MagicLinkService.create(self.user))
        self.assertIsNone(MagicLinkService.create(self.user))
