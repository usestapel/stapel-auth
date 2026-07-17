"""System check for mock OTP providers left on in production (tag ``stapel_auth``).

E-level by design: ``USE_MOCK_SMS_OTP``/``USE_MOCK_EMAIL_OTP`` are meant for
local dev only (the shipped ``.env.local`` preset turns them on so a login
tab works without real SMS/email providers wired up — the code is written to
logs instead of actually sent). If either mock flag survives into a
``DEBUG=False`` boot, real users get a channel that looks enabled
(oauth/services.py.AuthCapabilities no longer gates ``enabled`` on the mock
flag — see the email_mock/phone_mock/methods[].mock transparency fields
instead) but whose OTP code never leaves the process: users can't complete
login/registration over that channel, and anyone with log access can
authenticate as anyone. This is exactly the "deployed as downloaded" class of
mistake ``stapel_core.django.prodguard`` exists to catch for secrets/DB
passwords — same failure shape, so it gets the same treatment here rather
than only being caught by the standalone ``deploy/check-env.sh`` text-file
gate (which does not run inside the app process/CI's ``manage.py check``).
"""
from __future__ import annotations

from django.core import checks

E001_MOCK_OTP_IN_PRODUCTION = "stapel_auth.E001"


@checks.register("stapel_auth")
def check_mock_otp_disabled_in_production(app_configs=None, **kwargs):
    """E001 — USE_MOCK_SMS_OTP/USE_MOCK_EMAIL_OTP must be off when DEBUG=False."""
    from django.conf import settings

    if getattr(settings, "DEBUG", False):
        return []

    from .conf import auth_settings

    errors = []
    if auth_settings.USE_MOCK_SMS_OTP:
        errors.append(checks.Error(
            "USE_MOCK_SMS_OTP is enabled with DEBUG=False. Phone OTP codes "
            "are being written to logs instead of sent via SMS — real users "
            "cannot complete phone login/registration, and anyone with log "
            "access can authenticate as anyone.",
            hint="Set STAPEL_AUTH['USE_MOCK_SMS_OTP'] = False (or unset the "
                 "USE_MOCK_SMS_OTP env var) and configure a real SMS "
                 "provider before deploying with DEBUG=False.",
            id=E001_MOCK_OTP_IN_PRODUCTION,
        ))
    if auth_settings.USE_MOCK_EMAIL_OTP:
        errors.append(checks.Error(
            "USE_MOCK_EMAIL_OTP is enabled with DEBUG=False. Email OTP "
            "codes are being written to logs instead of sent via email — "
            "real users cannot complete email login/registration, and "
            "anyone with log access can authenticate as anyone.",
            hint="Set STAPEL_AUTH['USE_MOCK_EMAIL_OTP'] = False (or unset "
                 "the USE_MOCK_EMAIL_OTP env var) and configure a real email "
                 "provider before deploying with DEBUG=False.",
            id=E001_MOCK_OTP_IN_PRODUCTION,
        ))
    return errors


__all__ = ["E001_MOCK_OTP_IN_PRODUCTION", "check_mock_otp_disabled_in_production"]
