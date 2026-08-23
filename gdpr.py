"""The Art. 15 export, and the registry seam onto the Art. 17 erasure.

The erasure itself is not here: it lives in :mod:`stapel_auth.erasure`, as
one function the in-process registry (below) and the comm subscribers
registered in ``apps.ready()`` both reach. Two callers, one implementation —
a monolith and a fleet erase the same rows the same way, and there is no
second erasure to drift.
"""
from stapel_core.gdpr import GDPRProvider

from .erasure import erase_subject, store_reregistration_hashes, user_identifiers


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
        """Erase the subject — the same operation the comm path runs.

        The registry reaches the erasure here; the ``gdpr.erasure.requested``
        subscriber registered in ``apps.ready()`` reaches it there. Auth
        hosts stapel-gdpr, so in the fleet's own deployment both callers run
        in one process for one account — the second finds nothing left and
        says so, and the orchestrator writes one receipt either way (see
        :mod:`stapel_auth.erasure`).
        """
        erase_subject('account', user_id)

    def anonymize(self, user_id: int) -> None:
        # Auth data is fully deleted — nothing to anonymize
        pass

    # -------------------------------------------------------------------------
    # Thin seams onto stapel_auth.erasure — the implementation is there, and
    # these stay because the export above and callers outside this class ask
    # the provider for them.

    def _user_identifiers(self, user_id: int) -> list[str]:
        return user_identifiers(user_id)

    def _store_reregistration_hashes(self, user_id: int) -> None:
        store_reregistration_hashes(user_id)


def _serialize_dates(rows: list[dict]) -> list[dict]:
    """Convert datetime objects to ISO strings for JSON serialisation."""
    result = []
    for row in rows:
        result.append({
            k: v.isoformat() if hasattr(v, 'isoformat') else v
            for k, v in row.items()
        })
    return result
