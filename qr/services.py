"""Service classes for QR auth domain."""
import secrets
import json as _json

from stapel_auth.qr.dto import QRType, QRStatus


class QRAuthService:
    """
    Short-lived QR auth keys stored in Redis.

    Types:
      session_share  – logged-in user shares session with a scanner.
      login_request  – unauth device requests login approval from a logged-in scanner.
    """
    PREFIX = "qr_auth"
    TTL = 300  # 5 minutes

    @classmethod
    def _key(cls, key: str) -> str:
        return f"{cls.PREFIX}:{key}"

    @classmethod
    def generate(cls, *, qr_type: QRType, owner_user_id=None, redirect_url: str = None,
                 nonce: str = None, allow_unauthenticated_scanner: bool = False) -> str:
        """Create a QR record.

        nonce — random secret bound to the generating device via an httponly
        cookie; required to poll a login_request key.
        allow_unauthenticated_scanner — session_share only: explicitly allow
        an unauthenticated scanner to receive the owner's session.
        """
        from django.core.cache import cache
        key = secrets.token_urlsafe(20)
        cache.set(cls._key(key), _json.dumps({
            "type": qr_type,
            "status": QRStatus.PENDING,
            "owner_user_id": str(owner_user_id) if owner_user_id else None,
            "redirect_url": redirect_url or None,
            "nonce": nonce or None,
            "allow_unauthenticated_scanner": bool(allow_unauthenticated_scanner),
        }), cls.TTL)
        return key

    @classmethod
    def get(cls, key: str) -> dict | None:
        from django.core.cache import cache
        raw = cache.get(cls._key(key))
        return _json.loads(raw) if raw else None

    @classmethod
    def _update(cls, key: str, data: dict) -> None:
        from django.core.cache import cache
        cache.set(cls._key(key), _json.dumps(data), cls.TTL)

    @classmethod
    def fulfill_session_share(cls, key: str, *, scanner_user_id) -> bool:
        data = cls.get(key)
        if not data or data['status'] != QRStatus.PENDING:
            return False
        data['status'] = QRStatus.FULFILLED
        data['fulfilled_user_id'] = str(scanner_user_id)
        cls._update(key, data)
        return True

    @classmethod
    def fulfill_login_request(cls, key: str, *, approver_user_id, access_token: str, refresh_token: str) -> bool:
        data = cls.get(key)
        if not data or data['status'] != QRStatus.PENDING:
            return False
        data['status'] = QRStatus.FULFILLED
        data['fulfilled_user_id'] = str(approver_user_id)
        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        cls._update(key, data)
        return True

    @classmethod
    def reject(cls, key: str) -> bool:
        data = cls.get(key)
        if not data or data['status'] != QRStatus.PENDING:
            return False
        data['status'] = QRStatus.REJECTED
        cls._update(key, data)
        return True

    @classmethod
    def delete(cls, key: str) -> None:
        from django.core.cache import cache
        cache.delete(cls._key(key))
