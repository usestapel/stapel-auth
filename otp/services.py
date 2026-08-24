"""
OTP (One-Time Password) service classes for phone and email verification,
and authenticator change flows.

Codes live in :class:`stapel_core.verification.codes.OneTimeCodeStore` — a
hashed, TTL-scoped cache entry — not in a table. What stays here is the policy
the store deliberately does not own: how long a code lives, how many guesses it
survives, how often one may be asked for, how it is generated and how it is
delivered. See the core module for why a bearer credential with a ten-minute
life has no business in a row.
"""
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging
import secrets
import uuid

from stapel_core.verification.codes import (
    CodeOutcome,
    OneTimeCodeStore,
    StoreUnavailable,
)

from stapel_auth.otp.constants import OTP_CODE_LENGTH  # noqa: F401 — re-exported

logger = logging.getLogger(__name__)

#: One store per code family. Separate purposes, so a code sent to an address
#: can never satisfy a challenge on a number.
email_code_store = OneTimeCodeStore("otp_email")
phone_code_store = OneTimeCodeStore("otp_phone")


def promote_anonymous_session(user, *, auth_type: str) -> None:
    """Flip an anonymous guest account to registered.

    THE IDENTITY MODEL: a user becomes registered exactly when a verified
    identity ANCHOR (email, phone, or a federated identity) is attached to
    their account — never for a mere credential (password/passkey/TOTP). The
    ONE opt-in exception is a deployment that sets
    ``AUTH_PASSWORD_DEANONYMIZES=True`` to run classic login/password accounts,
    where password-only register() promotes with ``auth_type="password"``;
    that policy decision lives in the caller (password/views.py), not here.
    Call this once the caller has ALREADY set the anchor field(s) (email/
    phone/oauth_provider+oauth_id/etc.) and the matching ``is_*_verified``
    flag on *user*; this only flips the anonymous state itself and upgrades
    the placeholder ``anon_*`` username.

    Does NOT call ``.save()`` — the caller saves once, together with the
    anchor field(s) it just set (matching the historical single-write
    behavior of the inline branches this factors out; if the caller uses
    ``update_fields``, remember to include ``is_anonymous``, ``auth_type``
    and ``username``).
    """
    user.is_anonymous = False
    user.auth_type = auth_type
    user.upgrade_username_from_anonymous()


def _generate_numeric_code(length: int) -> str:
    """A random ``length``-digit numeric string with no leading zero."""
    lo = 10 ** (length - 1)
    span = 9 * lo
    return str(secrets.randbelow(span) + lo)


#: channel -> the setting that decides whether that channel is mocked.
_MOCK_FLAG_BY_CHANNEL = {
    'email': 'USE_MOCK_EMAIL_OTP',
    'phone': 'USE_MOCK_SMS_OTP',
}


def issued_code_length(channel: str, *, force_real: bool = False) -> int:
    """Digits in the code this deployment ACTUALLY issues on *channel*.

    THE SINGLE SOURCE for that number. Two consumers used to compute it
    independently: the generation path (``_OtpCodeService.generate_code``)
    and the capabilities contract the frontend builds its code input from
    (``oauth/services.py`` -> ``OtpMeta.email_code_length`` /
    ``phone_code_length``). They agreed only by coincidence, and stopped the
    moment a deployment turned a mock channel on with a ``MOCK_OTP_CODE``
    narrower than ``OTP_LENGTH``: the server issued ``'0000'`` while the
    contract promised six boxes, so the code could not be typed in. Issuance
    and contract now read the same function; there is no second computation.

    A mocked channel issues ``MOCK_OTP_CODE`` verbatim, so its width IS that
    string's; every other case issues a random ``OTP_LENGTH``-digit code.
    *force_real* is the generation path's admin escape hatch (see
    ``generate_code``): it asks for the real width even on a mocked channel,
    and is never what the contract reports — the contract describes the code
    an ordinary caller receives.
    """
    from stapel_auth.conf import auth_settings

    flag = _MOCK_FLAG_BY_CHANNEL.get(channel)
    if flag and not force_real and bool(getattr(auth_settings, flag)):
        return len(str(auth_settings.MOCK_OTP_CODE or ''))
    return int(auth_settings.OTP_LENGTH)


def _result_for(check, *, block_duration: int) -> dict:
    """Translate a store verdict into this service's result envelope.

    The ``NOT_FOUND`` arm is the whole point. Nothing waiting means the wait
    expired — aged out, already spent, or the cache restarted — and the user is
    owed an invitation to start over, not the accusation that they mistyped.
    The table this replaced answered ``invalid_code`` to all three.
    """
    if check.outcome is CodeOutcome.OK:
        return {'success': True}
    if check.outcome is CodeOutcome.NOT_FOUND:
        return {'error': 'expired'}
    if check.outcome is CodeOutcome.BLOCKED:
        return {'error': 'blocked', 'retry_after': check.retry_after or block_duration}
    if check.outcome is CodeOutcome.UNAVAILABLE:
        # Fail closed, and say so honestly: "we could not ask" is not
        # "you may not", and must never be rendered as a wrong code.
        return {'error': 'unavailable'}
    return {
        'error': 'invalid_code',
        'attempts_remaining': max(check.attempts_remaining or 0, 0),
    }


class _OtpCodeService:
    """Shared OTP mechanics for the phone and email services.

    Subclasses supply the store, the mock-mode switch and the delivery kwargs;
    everything the two flows did identically lives here once.
    """

    #: The core store this service issues into.
    store: OneTimeCodeStore
    #: What the log calls the thing being verified.
    channel = ''

    # Read at call time, not in __init__: this package's rule everywhere
    # else, and the reason it matters here is mundane — a long-lived
    # service instance would otherwise freeze whatever the settings said
    # when it was built.
    @property
    def max_attempts(self) -> int:
        """Wrong codes allowed before the block. OTP_MAX_ATTEMPTS shipped in
        conf.py from day one and was read by nobody — the checks hardcoded
        5, so a host that raised it still got 5 with no way to tell."""
        from stapel_auth.conf import auth_settings

        return int(auth_settings.OTP_MAX_ATTEMPTS)

    @property
    def block_duration(self) -> int:
        """Seconds the block lasts. Was a literal timedelta(minutes=10)."""
        from stapel_auth.conf import auth_settings

        return int(auth_settings.OTP_BLOCK_DURATION)

    @property
    def hourly_limit(self) -> int:
        """Sends per hour per identifier. OTP_RATE_LIMIT_PER_HOUR was the
        sibling of OTP_MAX_ATTEMPTS: shipped, documented, and read by
        nobody — the resend cooldown was the only send-side throttle."""
        from stapel_auth.conf import auth_settings

        return int(auth_settings.OTP_RATE_LIMIT_PER_HOUR)

    def generate_code(self, force_real=False):
        """Generate a verification code ``issued_code_length(self.channel)``
        digits wide — the same width the capabilities contract reports.

        The mock arm returns ``MOCK_OTP_CODE`` verbatim, which is what makes
        that function's mock answer true by construction; the real arm asks
        the same function for the real width. One computation, two consumers.

        Args:
            force_real: If True, generate real OTP even in mock mode (for admin accounts)
        """
        if self.use_mock_otp and not force_real:
            return self.mock_code
        return _generate_numeric_code(issued_code_length(self.channel, force_real=True))

    def _deliver(self, identifier: str, code: str) -> bool:
        """Queue the notification carrying *code*. Subclass hook."""
        raise NotImplementedError

    def send_verification_code(self, identifier, device_id=None, force_real_otp=False,
                               deliver=True):
        """Issue a code for *identifier* and (usually) send it.

        *deliver* ``False`` runs the whole flow — the same rate-limit and block
        bookkeeping, the same stored code, the same return value — but sends
        nothing, and the stored code is always a real random one (never the
        mock code). That is the 'silent' arm of
        ``AUTH_REGISTRATION_CLOSED_BEHAVIOR`` (registration.py): a stranger
        must be indistinguishable from a member on this endpoint, which they
        would not be if the code, the cooldown or the block state were skipped
        for them.

        Returns the store's receipt on success, an error envelope when a limit
        or a block refuses the send, and ``None`` when nothing could be sent.
        """
        try:
            wait = self.store.send_wait(
                identifier,
                cooldown=self.resend_cooldown,
                hourly_limit=self.hourly_limit,
                device_id=device_id,
            )
            if wait:
                logger.warning(f"Rate limit exceeded for {self.channel}")
                return {'error': 'rate_limit', 'retry_after': wait}

            blocked = self.store.blocked_for(identifier)
            if blocked:
                logger.warning(f"{self.channel} is blocked for {blocked}s")
                return {'error': 'blocked', 'retry_after': blocked}

            # Generate code (force real OTP for admin accounts; an
            # undelivered code is ALWAYS real — the mock code is public)
            code = self.generate_code(force_real=force_real_otp or not deliver)

            # Issuing is what spends the cooldown and the hourly slot, so a
            # send refused above costs the user nothing.
            issued = self.store.issue(
                identifier,
                code,
                ttl=self.otp_ttl,
                max_attempts=self.max_attempts,
                device_id=device_id,
            )

            if not deliver:
                # Nothing is sent and nothing is logged about the code — the
                # caller's answer is the ordinary success envelope.
                return issued

            if self.use_mock_otp and not force_real_otp:
                # The code is MOCK_OTP_CODE by construction; logging it would
                # print a credential to say something the setting already says.
                logger.info(f"Mock OTP mode - code issued for {self.channel}")
                return issued

            if not self._deliver(identifier, code):
                logger.error(f"Failed to queue OTP notification for {self.channel}")
                self.store.discard(identifier)
                return None

            logger.info(f"Verification code sent to {self.channel}")
            return issued
        except StoreUnavailable:
            # No store, no code. Refusing to send beats sending one that
            # nothing can later verify.
            logger.error(f"OTP store unavailable; no code issued for {self.channel}")
            return None
        except Exception as e:
            logger.error(f"Failed to send verification code: {e}")
            return None

    def verify_code(self, identifier, code):
        """Check *code* for *identifier*.

        A match spends the entry, so a code works exactly once. A miss bumps
        the attempt counter that lives inside the same entry — one lifetime for
        both, so a fresh code always arrives with a fresh budget.
        """
        try:
            check = self.store.check(
                identifier, code, block_seconds=self.block_duration
            )
            result = _result_for(check, block_duration=self.block_duration)
            if check.outcome is CodeOutcome.MISMATCH:
                logger.warning(
                    f"Invalid code for {self.channel}, "
                    f"{result['attempts_remaining']} attempts left"
                )
            elif check.outcome is CodeOutcome.BLOCKED:
                logger.warning(f"Verification blocked for {self.channel}")
            return result
        except Exception as e:
            logger.error(f"Failed to verify code: {e}")
            return {'error': 'server_error'}


class PhoneVerificationService(_OtpCodeService):
    """
    Service for phone verification using Twilio
    """

    store = phone_code_store
    channel = 'phone'

    def __init__(self):
        from stapel_auth.conf import auth_settings

        self.account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
        self.auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
        self.verify_service_sid = getattr(settings, 'TWILIO_VERIFY_SERVICE_SID', '')
        self.use_mock_otp = auth_settings.USE_MOCK_SMS_OTP
        self.mock_code = auth_settings.MOCK_OTP_CODE
        self.otp_ttl = auth_settings.OTP_TTL
        self.resend_cooldown = auth_settings.OTP_RESEND_COOLDOWN

    # Thin overrides: `phone=` / `email=` are keyword arguments callers pass
    # by name, so the parameter is part of the signature, not an internal one.
    def send_verification_code(self, phone, device_id=None, force_real_otp=False,
                               deliver=True):
        return super().send_verification_code(
            phone, device_id, force_real_otp=force_real_otp, deliver=deliver
        )

    def verify_code(self, phone, code):
        return super().verify_code(phone, code)

    def _deliver(self, identifier, code) -> bool:
        from django.utils.translation import get_language

        from stapel_core.notifications import request_notification

        return bool(request_notification(
            notification_type="otp_code",
            phone=identifier,
            variables={"code": code, "expiry_minutes": self.otp_ttl // 60},
            source_service="auth",
            language=get_language(),
        ))


class EmailVerificationService(_OtpCodeService):
    """
    Service for email verification using OTP
    """

    store = email_code_store
    channel = 'email'

    def __init__(self):
        from stapel_auth.conf import auth_settings

        self.use_mock_otp = auth_settings.USE_MOCK_EMAIL_OTP
        self.mock_code = auth_settings.MOCK_OTP_CODE
        self.otp_ttl = auth_settings.OTP_TTL
        self.resend_cooldown = auth_settings.OTP_RESEND_COOLDOWN

    def send_verification_code(self, email, device_id=None, force_real_otp=False,
                               deliver=True):
        return super().send_verification_code(
            email, device_id, force_real_otp=force_real_otp, deliver=deliver
        )

    def verify_code(self, email, code):
        return super().verify_code(email, code)

    def _deliver(self, identifier, code) -> bool:
        from django.utils.translation import get_language

        from stapel_core.notifications import request_notification

        return bool(request_notification(
            notification_type="otp_code",
            email=identifier,
            variables={"code": code, "expiry_minutes": self.otp_ttl // 60},
            source_service="auth",
            language=get_language(),
        ))


class AuthenticatorChangeService:
    """
    Service for authenticator (phone/email) change flows.
    Supports instant (double OTP) and delayed (14-day) flows.
    """

    CHANGE_TOKEN_LIFETIME = timedelta(minutes=30)
    DELAYED_PERIOD_DAYS = 14

    def __init__(self):
        self.phone_service = PhoneVerificationService()
        self.email_service = EmailVerificationService()

    # ── Instant flow ─────────────────────────────────────────

    def request_old_otp(self, user, change_type, device_id=None):
        """Send OTP to the user's current phone/email."""
        from stapel_auth.utils import mask_value

        if change_type == 'phone':
            target = user.phone
            if not target:
                return {'error': 'no_current_value', 'message': 'No phone number on this account.'}
            result = self.phone_service.send_verification_code(target, device_id)
        else:
            target = user.email
            if not target:
                return {'error': 'no_current_value', 'message': 'No email address on this account.'}
            result = self.email_service.send_verification_code(target, device_id)

        if isinstance(result, dict) and result.get('error'):
            return result

        if result is None:
            return {'error': 'send_failed'}

        return {'success': True, 'masked_target': mask_value(target, change_type)}

    def verify_old_otp(self, user, change_type, code):
        """
        Verify OTP sent to the user's current phone/email.
        On success, creates an AuthenticatorChangeRequest with change_token.
        """
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        target = user.phone if change_type == 'phone' else user.email
        if not target:
            return {'error': 'no_current_value'}

        if change_type == 'phone':
            result = self.phone_service.verify_code(target, code)
        else:
            result = self.email_service.verify_code(target, code)

        if isinstance(result, dict) and not result.get('success'):
            return result

        # Cancel any existing pending instant request for this user+type (atomic to prevent race)
        from django.db import transaction, IntegrityError

        change_token = uuid.uuid4()
        expires_at = timezone.now() + self.CHANGE_TOKEN_LIFETIME

        try:
            with transaction.atomic():
                AuthenticatorChangeRequest.objects.filter(
                    user=user,
                    change_type=change_type,
                    status=AuthenticatorChangeStatus.PENDING,
                    scheduled_at__isnull=True,
                ).update(status=AuthenticatorChangeStatus.CANCELLED, cancelled_at=timezone.now())

                AuthenticatorChangeRequest.objects.create(
                    user=user,
                    change_type=change_type,
                    old_value=target,
                    new_value='',  # Not known yet
                    status=AuthenticatorChangeStatus.PENDING,
                    change_token=change_token,
                )
        except IntegrityError:
            return {'error': 'duplicate_request', 'message': 'A pending change request already exists.'}

        return {
            'success': True,
            'change_token': str(change_token),
            'expires_at': expires_at.isoformat(),
        }

    def request_new_otp(self, user, change_type, new_value, change_token):
        """Validate change_token, check availability, send OTP to new_value."""

        request_obj = self._get_valid_change_request(user, change_type, change_token)
        if request_obj is None:
            return {'error': 'invalid_change_token', 'message': 'Invalid or expired change token.'}

        available = self.is_value_available(new_value, change_type, exclude_user=user)
        if not available:
            return {'error': 'not_available'}

        # Store new_value on the request
        request_obj.new_value = new_value
        request_obj.save(update_fields=['new_value'])

        if change_type == 'phone':
            result = self.phone_service.send_verification_code(new_value)
        else:
            result = self.email_service.send_verification_code(new_value)

        if isinstance(result, dict) and result.get('error'):
            return result

        if result is None:
            return {'error': 'send_failed'}

        return {'success': True}

    def verify_new_and_apply(self, user, change_type, new_value, code, change_token):
        """Verify OTP for new value, apply the change, invalidate tokens."""
        from stapel_auth.models import AuthenticatorChangeStatus

        request_obj = self._get_valid_change_request(user, change_type, change_token)
        if request_obj is None:
            return {'error': 'invalid_change_token', 'message': 'Invalid or expired change token.'}

        if request_obj.new_value != new_value:
            return {'error': 'value_mismatch', 'message': 'New value does not match the change request.'}

        if change_type == 'phone':
            result = self.phone_service.verify_code(new_value, code)
        else:
            result = self.email_service.verify_code(new_value, code)

        if isinstance(result, dict) and not result.get('success'):
            return result

        # Apply
        self._apply_change(user, change_type, new_value)

        request_obj.status = AuthenticatorChangeStatus.COMPLETED
        request_obj.completed_at = timezone.now()
        request_obj.save(update_fields=['status', 'completed_at'])

        self._invalidate_all_tokens(user)

        return {'success': True}

    # ── Delayed flow ─────────────────────────────────────────

    def initiate_delayed(self, user, change_type, new_value, device_id='', ip=None, user_agent=''):
        """Create a pending delayed change request (14-day waiting period)."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        old_value = user.phone if change_type == 'phone' else user.email
        if not old_value:
            return {'error': 'no_current_value', 'message': f'No {change_type} on this account.'}

        available = self.is_value_available(new_value, change_type, exclude_user=user)
        if not available:
            return {'error': 'not_available'}

        # Cancel any existing pending request for this user+type
        # (covers both delayed and instant flows to avoid unique constraint violation)
        AuthenticatorChangeRequest.objects.filter(
            user=user,
            change_type=change_type,
            status=AuthenticatorChangeStatus.PENDING,
        ).update(status=AuthenticatorChangeStatus.CANCELLED, cancelled_at=timezone.now())

        scheduled_at = timezone.now() + timedelta(days=self.DELAYED_PERIOD_DAYS)

        request_obj = AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type=change_type,
            old_value=old_value,
            new_value=new_value,
            scheduled_at=scheduled_at,
            device_id=device_id,
            ip_address=ip,
            user_agent=user_agent,
        )

        return {
            'success': True,
            'change_request_id': str(request_obj.id),
            'scheduled_at': scheduled_at.isoformat(),
        }

    def initiate_delayed_totp(self, user, device_id='', ip=None, user_agent=''):
        """Delayed TOTP removal — for a user who LOST their device (cannot
        produce a code or a backup code), so the instant proof-gated path
        (``mfa.services.TOTPService.setup``/``disable``) is unavailable.

        Unlike the phone/email delayed flow there is no "new address" to
        pre-commit: this schedules a DISABLE (same ``scheduled_at``/
        cancel/notify machinery, `DELAYED_PERIOD_DAYS`-day cooldown). Once
        it executes (``tasks.execute_pending_changes``), the account has no
        TOTP device and the user re-enrolls via the normal instant
        ``setup``/``confirm_setup`` pair — this IS the "replace", just
        split at the safety boundary instead of pre-provisioning a secret
        the user can't act on until the window closes anyway.

        Requires a verified email or phone — that is the channel the
        day-1/7/13 notifications and the legitimate owner's cancellation
        depend on. A user with a lost TOTP device AND no verified contact
        has no self-serve path left; this returns 'no_verified_contact'
        deliberately rather than silently degrading to an unnotified,
        uncancellable change — that combination is a support case.
        """
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from stapel_auth.mfa.services import TOTPService

        if not TOTPService.is_enabled(user):
            return {'error': 'not_enabled', 'message': 'TOTP is not enabled on this account.'}

        has_verified_contact = (
            (user.email and getattr(user, 'is_email_verified', False))
            or (user.phone and getattr(user, 'is_phone_verified', False))
        )
        if not has_verified_contact:
            return {
                'error': 'no_verified_contact',
                'message': (
                    'A verified email or phone is required to request a delayed '
                    'TOTP change (used to notify you and let you cancel it). '
                    'This account has neither — contact support.'
                ),
            }

        # Cancel any existing pending TOTP change request for this user.
        AuthenticatorChangeRequest.objects.filter(
            user=user,
            change_type='totp',
            status=AuthenticatorChangeStatus.PENDING,
        ).update(status=AuthenticatorChangeStatus.CANCELLED, cancelled_at=timezone.now())

        scheduled_at = timezone.now() + timedelta(days=self.DELAYED_PERIOD_DAYS)

        request_obj = AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type='totp',
            old_value='',
            # Opaque, unique-per-request marker — satisfies the
            # unique_pending_reservation constraint (fields=[new_value,
            # change_type], condition=pending); TOTP has no real "new
            # value" to reserve, so this is never displayed (see
            # get_pending_status's 'authenticator app' override).
            new_value=f'totp:{uuid.uuid4().hex}',
            scheduled_at=scheduled_at,
            device_id=device_id,
            ip_address=ip,
            user_agent=user_agent,
        )

        return {
            'success': True,
            'change_request_id': str(request_obj.id),
            'scheduled_at': scheduled_at.isoformat(),
        }

    def get_pending_status(self, user, change_type):
        """Return pending delayed change info or None."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from stapel_auth.utils import mask_value

        request_obj = AuthenticatorChangeRequest.objects.filter(
            user=user,
            change_type=change_type,
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at__isnull=False,
        ).first()

        if not request_obj:
            return None

        days_remaining = max(0, (request_obj.scheduled_at - timezone.now()).days)
        notifications_sent = []
        if request_obj.notification_day_1_sent:
            notifications_sent.append('day_1')
        if request_obj.notification_day_7_sent:
            notifications_sent.append('day_7')
        if request_obj.notification_day_13_sent:
            notifications_sent.append('day_13')

        # TOTP has no "new address" — new_value is an opaque internal
        # reservation marker (see AuthenticatorChangeRequest docstring),
        # never meant for display.
        if request_obj.change_type == 'totp':
            new_value_masked = 'authenticator app'
        else:
            new_value_masked = mask_value(request_obj.new_value, request_obj.change_type)

        return {
            'change_request_id': str(request_obj.id),
            'type': request_obj.change_type,
            'new_value_masked': new_value_masked,
            'created_at': request_obj.created_at.isoformat(),
            'scheduled_at': request_obj.scheduled_at.isoformat(),
            'days_remaining': days_remaining,
            'notifications_sent': notifications_sent,
        }

    def cancel_pending(self, user, change_type, change_request_id):
        """Cancel a pending delayed change request."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        try:
            request_obj = AuthenticatorChangeRequest.objects.get(
                id=change_request_id,
                user=user,
                change_type=change_type,
                status=AuthenticatorChangeStatus.PENDING,
            )
        except AuthenticatorChangeRequest.DoesNotExist:
            return {'error': 'not_found', 'message': 'Change request not found.'}

        request_obj.status = AuthenticatorChangeStatus.CANCELLED
        request_obj.cancelled_at = timezone.now()
        request_obj.save(update_fields=['status', 'cancelled_at'])

        return {'success': True}

    # ── Shared helpers ───────────────────────────────────────

    @staticmethod
    def is_value_available(value, change_type, exclude_user=None):
        """Check if a phone/email is available (not registered AND not reserved)."""
        from django.contrib.auth import get_user_model
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        User = get_user_model()

        if change_type == 'phone':
            qs = User.objects.filter(phone=value)
        else:
            qs = User.objects.filter(email=value)
        if exclude_user:
            qs = qs.exclude(id=exclude_user.id)
        if qs.exists():
            return False

        # Check reservation by pending change
        if AuthenticatorChangeRequest.objects.filter(
            new_value=value,
            change_type=change_type,
            status=AuthenticatorChangeStatus.PENDING,
        ).exists():
            return False

        return True

    @staticmethod
    def _apply_change(user, change_type, new_value):
        """Update the user's phone/email field and publish contact-changed event."""
        if change_type == 'phone':
            user.phone = new_value
            user.is_phone_verified = True
        else:
            user.email = new_value
            user.is_email_verified = True
        user.save()

        # Publish user-contact-changed event for notifications service
        try:
            from stapel_core.bus import publish, Event
            from stapel_core.kafka.topics import TOPIC_USER_CONTACT_CHANGED
            from stapel_core.kafka.events import EventType
            publish(
                TOPIC_USER_CONTACT_CHANGED,
                Event(
                    event_type=EventType.USER_CONTACT_CHANGED,
                    service="auth",
                    payload={
                        "user_id": str(user.id),
                        "email": user.email or "",
                        "phone": user.phone or "",
                    },
                    key=str(user.id),
                ),
            )
        except Exception:
            logger.exception("Failed to publish user-contact-changed event")

    @staticmethod
    def _invalidate_all_tokens(user):
        """Blacklist all refresh tokens for this user via RefreshTokenTracker + Redis."""
        from stapel_auth.models import RefreshTokenTracker

        # Mark all tracked refresh tokens as revoked
        RefreshTokenTracker.objects.filter(user=user, is_revoked=False).update(is_revoked=True)

        # Also blacklist via Redis if available
        try:
            from stapel_core.core.token_blacklist import TokenBlacklist
            from stapel_core.core.jwt_handler import JWTHandler
            from stapel_core.django.jwt.utils import load_jwt_config_from_settings
            from datetime import datetime, timezone as dt_timezone

            blacklist = TokenBlacklist()
            config = load_jwt_config_from_settings()
            jwt_handler = JWTHandler(config)

            tokens = RefreshTokenTracker.objects.filter(user=user)
            for tracker in tokens:
                try:
                    payload = jwt_handler.decode_token(tracker.token, verify=False)
                    if payload and 'jti' in payload:
                        exp = payload.get('exp')
                        if exp:
                            expires_in = datetime.fromtimestamp(exp, tz=dt_timezone.utc) - datetime.now(dt_timezone.utc)
                            if expires_in.total_seconds() > 0:
                                blacklist.blacklist_token(payload['jti'], expires_in)
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Failed to blacklist tokens via Redis for user {user.id}: {e}")

    def _get_valid_change_request(self, user, change_type, change_token):
        """Get a pending instant-flow change request by change_token."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        try:
            token_uuid = uuid.UUID(str(change_token))
        except (ValueError, AttributeError):
            return None

        try:
            request_obj = AuthenticatorChangeRequest.objects.get(
                user=user,
                change_type=change_type,
                change_token=token_uuid,
                status=AuthenticatorChangeStatus.PENDING,
            )
        except AuthenticatorChangeRequest.DoesNotExist:
            return None

        # Check if token has expired
        if request_obj.created_at + self.CHANGE_TOKEN_LIFETIME < timezone.now():
            return None

        return request_obj
