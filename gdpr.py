from stapel_core.gdpr import GDPRProvider


class AuthGDPRProvider(GDPRProvider):
    section = 'auth'

    def export(self, user_id: int) -> dict:
        from .models import (
            AuthAuditLog, AuthenticatorChangeRequest, LoginAttempt,
            OrgMembership, PasskeyCredential, TOTPDevice,
            UserSession,
        )
        sessions = list(UserSession.objects.filter(user_id=user_id).values(
            'device_name', 'device_type', 'created_at', 'last_used_at', 'expires_at', 'is_revoked',
        ))
        passkeys = list(PasskeyCredential.objects.filter(user_id=user_id).values(
            'device_name', 'transports', 'created_at', 'last_used_at', 'is_active',
        ))
        totp = list(TOTPDevice.objects.filter(user_id=user_id).values(
            'is_active', 'created_at', 'confirmed_at',
        ))
        login_attempts = list(LoginAttempt.objects.filter(
            identifier__in=self._user_identifiers(user_id),
        ).values('attempt_type', 'ip_address', 'user_agent', 'created_at'))
        audit_logs = list(AuthAuditLog.objects.filter(user_id=user_id).values(
            'event_type', 'ip_address', 'created_at',
        ))
        change_requests = list(AuthenticatorChangeRequest.objects.filter(user_id=user_id).values(
            'change_type', 'status', 'created_at', 'scheduled_at',
        ))
        memberships = list(OrgMembership.objects.filter(user_id=user_id).select_related('org').values(
            'org__name', 'org__slug', 'role', 'joined_at',
        ))
        return {
            'sessions':       _serialize_dates(sessions),
            'passkeys':       _serialize_dates(passkeys),
            'totp_devices':   _serialize_dates(totp),
            'login_attempts': _serialize_dates(login_attempts),
            'audit_log':      _serialize_dates(audit_logs),
            'authenticator_changes': _serialize_dates(change_requests),
            'sso_memberships': _serialize_dates(memberships),
        }

    def delete(self, user_id: int) -> None:
        from .models import (
            AuthAuditLog, AuthenticatorChangeRequest, EmailVerification,
            LoginAttempt, OrgMembership, PasskeyCredential,
            PhoneVerification, RefreshTokenTracker, TOTPDevice, UserSession,
        )
        self._store_reregistration_hashes(user_id)

        PhoneVerification.objects.filter(user_id=user_id).delete()
        EmailVerification.objects.filter(user_id=user_id).delete()
        RefreshTokenTracker.objects.filter(user_id=user_id).delete()
        UserSession.objects.filter(user_id=user_id).delete()
        TOTPDevice.objects.filter(user_id=user_id).delete()
        PasskeyCredential.objects.filter(user_id=user_id).delete()
        AuthenticatorChangeRequest.objects.filter(user_id=user_id).delete()
        LoginAttempt.objects.filter(
            identifier__in=self._user_identifiers(user_id),
        ).delete()
        AuthAuditLog.objects.filter(user_id=user_id).delete()
        OrgMembership.objects.filter(user_id=user_id).delete()

    def anonymize(self, user_id: int) -> None:
        # Auth data is fully deleted — nothing to anonymize
        pass

    # -------------------------------------------------------------------------

    def _user_identifiers(self, user_id: int) -> list[str]:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
            ids = []
            if user.email:
                ids.append(user.email)
            if hasattr(user, 'phone') and user.phone:
                ids.append(str(user.phone))
            return ids
        except User.DoesNotExist:
            return []

    def _store_reregistration_hashes(self, user_id: int) -> None:
        """Store irreversible hashes for re-registration detection (24-month retention)."""
        import hashlib
        from datetime import timedelta

        from django.contrib.auth import get_user_model
        from django.utils import timezone

        from stapel_gdpr.models import ReRegistrationHash

        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return

        expires_at = timezone.now() + timedelta(days=730)  # 24 months

        def _sha256(value: str) -> str:
            return hashlib.sha256(value.lower().strip().encode()).hexdigest()

        if user.email:
            ReRegistrationHash.objects.get_or_create(
                hash_type=ReRegistrationHash.TYPE_EMAIL,
                hash_value=_sha256(user.email),
                defaults={'user_id_was': user_id, 'expires_at': expires_at},
            )
        if hasattr(user, 'phone') and user.phone:
            ReRegistrationHash.objects.get_or_create(
                hash_type=ReRegistrationHash.TYPE_PHONE,
                hash_value=_sha256(str(user.phone)),
                defaults={'user_id_was': user_id, 'expires_at': expires_at},
            )


def _serialize_dates(rows: list[dict]) -> list[dict]:
    """Convert datetime objects to ISO strings for JSON serialisation."""
    result = []
    for row in rows:
        result.append({
            k: v.isoformat() if hasattr(v, 'isoformat') else v
            for k, v in row.items()
        })
    return result
