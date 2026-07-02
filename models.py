from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid
from datetime import timedelta


class PhoneVerification(models.Model):
    """
    Model to store phone verification codes
    """
    phone = models.CharField(max_length=18, db_index=True)
    code = models.CharField(max_length=4)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.IntegerField(default=0)
    device_id = models.CharField(max_length=255, db_index=True, null=True, blank=True)
    blocked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'phone_verifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['phone', 'created_at']),
            models.Index(fields=['device_id', 'created_at']),
        ]

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def is_blocked(self):
        """Check if verification is currently blocked"""
        if self.blocked_until:
            return timezone.now() < self.blocked_until
        return False

    def __str__(self):
        return f"{self.phone} - {self.code}"


class EmailVerification(models.Model):
    """
    Model to store email verification codes
    """
    email = models.EmailField(db_index=True)
    code = models.CharField(max_length=4)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.IntegerField(default=0)
    device_id = models.CharField(max_length=255, db_index=True, null=True, blank=True)
    blocked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'email_verifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'created_at']),
            models.Index(fields=['device_id', 'created_at']),
        ]

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def is_blocked(self):
        """Check if verification is currently blocked"""
        if self.blocked_until:
            return timezone.now() < self.blocked_until
        return False

    def __str__(self):
        return f"{self.email} - {self.code}"


class ServiceAPIKey(models.Model):
    """
    Model for service-to-service authentication
    """
    name = models.CharField(max_length=100, unique=True)
    key = models.CharField(max_length=255, unique=True, db_index=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    # Permissions
    allowed_endpoints = models.JSONField(default=list, blank=True)

    class Meta:
        db_table = 'service_api_keys'
        verbose_name = 'Service API Key'
        verbose_name_plural = 'Service API Keys'

    def __str__(self):
        return f"{self.name} - {'Active' if self.is_active else 'Inactive'}"

    @classmethod
    def generate_key(cls):
        """Generate a new API key"""
        return f"sk_{uuid.uuid4().hex}"


class RefreshTokenTracker(models.Model):
    """
    Track refresh tokens for additional security
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='refresh_tokens')
    token = models.CharField(max_length=500, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)
    device_info = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = 'refresh_token_tracker'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user} - {self.created_at}"


class DeviceType(models.TextChoices):
    PHONE   = 'phone',   'Phone'
    TABLET  = 'tablet',  'Tablet'
    DESKTOP = 'desktop', 'Desktop'
    API     = 'api',     'API'
    UNKNOWN = 'unknown', 'Unknown'


class UserSession(models.Model):
    """
    Represents one active login session tied to a refresh token.
    Enables refresh token rotation and session management.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sessions')
    # jti (JWT ID) of the current valid refresh token for this session.
    # Updated on every rotation; storing jti (not raw token) is safe if DB is compromised.
    jti = models.CharField(max_length=64, unique=True, db_index=True)
    access_jti = models.CharField(max_length=64, blank=True, db_index=True)
    device_name    = models.CharField(max_length=150, blank=True)
    device_type    = models.CharField(max_length=10, choices=DeviceType.choices, default=DeviceType.UNKNOWN, blank=True)
    device_details = models.CharField(max_length=150, blank=True)
    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_revoked    = models.BooleanField(default=False, db_index=True)
    is_suspicious = models.BooleanField(default=False)

    class Meta:
        db_table = 'user_sessions'
        ordering = ['-last_used_at']
        indexes = [
            models.Index(fields=['user', 'is_revoked']),
        ]

    def __str__(self):
        return f"{self.user} — {self.device_name or 'unknown device'} ({self.created_at:%Y-%m-%d})"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class TOTPDevice(models.Model):
    """
    TOTP second-factor device for a user (one per user).
    Secret stored plain — encrypt at rest via DB/volume encryption in prod.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='totp_device')
    secret = models.CharField(max_length=64)
    is_active = models.BooleanField(default=False)
    # Hashed backup codes: list of SHA-256 hex strings (8 codes).
    # Each code is consumed on use (removed from list).
    backup_codes = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'totp_devices'

    def __str__(self):
        return f"{self.user} TOTP ({'active' if self.is_active else 'pending'})"


class AuthenticatorChangeType(models.TextChoices):
    PHONE = 'phone', 'Phone'
    EMAIL = 'email', 'Email'


class AuthenticatorChangeStatus(models.TextChoices):
    PENDING = 'pending', 'Pending'
    COMPLETED = 'completed', 'Completed'
    CANCELLED = 'cancelled', 'Cancelled'
    EXPIRED = 'expired', 'Expired'


class AuthenticatorChangeRequest(models.Model):
    """
    Tracks pending authenticator (phone/email) change requests.
    Supports both instant (double OTP) and delayed (14-day) flows.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='auth_change_requests')

    change_type = models.CharField(max_length=10, choices=AuthenticatorChangeType)
    old_value = models.CharField(max_length=255)
    new_value = models.CharField(max_length=255)

    status = models.CharField(
        max_length=20,
        choices=AuthenticatorChangeStatus,
        default=AuthenticatorChangeStatus.PENDING,
    )

    # Links instant-flow steps (verify-old → request-new → verify-new)
    change_token = models.UUIDField(null=True, blank=True, db_index=True)

    # Only set for delayed flow
    scheduled_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)

    # Notification tracking (delayed flow)
    notification_day_1_sent = models.BooleanField(default=False)
    notification_day_7_sent = models.BooleanField(default=False)
    notification_day_13_sent = models.BooleanField(default=False)

    # Device / audit info
    device_id = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        db_table = 'authenticator_change_requests'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['new_value', 'status']),
            models.Index(fields=['scheduled_at', 'status']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'change_type'],
                condition=models.Q(status='pending'),
                name='unique_pending_change_per_user_type',
            ),
            models.UniqueConstraint(
                fields=['new_value', 'change_type'],
                condition=models.Q(status='pending'),
                name='unique_pending_reservation',
            ),
        ]

    def __str__(self):
        return f"{self.user} - {self.change_type} - {self.status}"


class LoginAttempt(models.Model):
    """
    Track login attempts for security purposes
    """
    identifier = models.CharField(max_length=255, db_index=True)  # email, phone, or IP
    attempt_type = models.CharField(max_length=20)  # 'success', 'failed', 'blocked'
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'login_attempts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['identifier', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
        ]

    def __str__(self):
        return f"{self.identifier} - {self.attempt_type} - {self.created_at}"


# =============================================================================
# Audit Log
# =============================================================================

class AuthEventType(models.TextChoices):
    LOGIN_SUCCESS       = 'login_success'
    LOGIN_FAILED        = 'login_failed'
    LOGOUT              = 'logout'
    PASSWORD_CHANGED    = 'password_changed'
    PASSWORD_RESET      = 'password_reset'
    TOTP_ENABLED        = 'totp_enabled'
    TOTP_DISABLED       = 'totp_disabled'
    TOTP_LOGIN          = 'totp_login'
    TOTP_STEP_UP        = 'totp_step_up'
    SESSION_REVOKED     = 'session_revoked'
    SESSION_REVOKE_ALL  = 'session_revoke_all'
    ACCOUNT_LOCKED      = 'account_locked'
    ACCOUNT_UNLOCK      = 'account_unlock'
    SUSPICIOUS_LOGIN    = 'suspicious_login'
    MAGIC_LINK_SENT     = 'magic_link_sent'
    MAGIC_LINK_USED     = 'magic_link_used'
    PASSKEY_REGISTERED  = 'passkey_registered'
    PASSKEY_LOGIN       = 'passkey_login'
    PASSKEY_REMOVED     = 'passkey_removed'
    OAUTH_LOGIN         = 'oauth_login'
    QR_LOGIN            = 'qr_login'
    SSO_LOGIN           = 'sso_login'
    TOTP_FAILED         = 'totp_failed'
    CAPTCHA_FAILED      = 'captcha_failed'


class AuthAuditLog(models.Model):
    id          = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user        = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='audit_logs')
    session     = models.ForeignKey('UserSession', on_delete=models.SET_NULL, null=True,
                                    blank=True, related_name='audit_logs')
    event_type  = models.CharField(max_length=50, choices=AuthEventType)
    ip_address  = models.GenericIPAddressField(null=True, blank=True)
    user_agent  = models.CharField(max_length=500, blank=True)
    metadata    = models.JSONField(default=dict)
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'auth_audit_log'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['event_type', 'created_at']),
        ]


# =============================================================================
# Passkeys (WebAuthn / FIDO2)
# =============================================================================

class PasskeyCredential(models.Model):
    id            = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user          = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='passkeys')
    credential_id = models.BinaryField(max_length=1024, unique=True)
    public_key    = models.BinaryField(max_length=4096)
    sign_count    = models.PositiveIntegerField(default=0)
    aaguid        = models.CharField(max_length=36, blank=True)
    device_name   = models.CharField(max_length=100, blank=True)
    transports    = models.JSONField(default=list)
    created_at    = models.DateTimeField(auto_now_add=True)
    last_used_at  = models.DateTimeField(null=True, blank=True)
    is_active     = models.BooleanField(default=True)

    class Meta:
        db_table = 'passkey_credentials'
        indexes = [models.Index(fields=['user', 'is_active'])]

# =============================================================================
# SSO — Organizations and Identity Provider Configs
# =============================================================================

class Organization(models.Model):
    id           = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name         = models.CharField(max_length=200)
    slug         = models.SlugField(max_length=100, unique=True)
    domain       = models.CharField(max_length=253, unique=True, blank=True, default='',
                                    help_text='Email domain tied to this org, e.g. acmecorp.com')
    sso_enforced = models.BooleanField(default=False,
                                       help_text='If true, members must log in via SSO only')
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sso_organizations'

    def __str__(self):
        return f'{self.name} ({self.slug})'


class SSOConfig(models.Model):
    PROTOCOL_SAML = 'saml'
    PROTOCOL_OIDC = 'oidc'
    PROTOCOL_CHOICES = [
        (PROTOCOL_SAML, 'SAML 2.0'),
        (PROTOCOL_OIDC, 'OIDC'),
    ]

    org       = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name='sso_config')
    protocol  = models.CharField(max_length=10, choices=PROTOCOL_CHOICES)
    is_active = models.BooleanField(default=True)

    # SAML fields
    saml_entity_id     = models.CharField(max_length=500, blank=True, help_text='IdP entity ID / issuer')
    saml_sso_url       = models.URLField(blank=True, help_text='IdP SSO URL (redirect binding)')
    saml_slo_url       = models.URLField(blank=True, help_text='IdP SLO URL (optional)')
    saml_x509_cert     = models.TextField(blank=True, help_text='IdP signing certificate (PEM or raw base64)')
    saml_name_id_format = models.CharField(
        max_length=200, blank=True,
        default='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    )

    # SAML attribute mapping (key = attribute name in assertion)
    attr_email      = models.CharField(max_length=200, blank=True, default='email')
    attr_first_name = models.CharField(max_length=200, blank=True, default='firstName')
    attr_last_name  = models.CharField(max_length=200, blank=True, default='lastName')

    # OIDC fields
    oidc_client_id     = models.CharField(max_length=200, blank=True)
    oidc_client_secret = models.CharField(max_length=500, blank=True)
    oidc_discovery_url = models.URLField(blank=True, help_text='.well-known/openid-configuration URL')
    oidc_scopes        = models.CharField(max_length=200, blank=True, default='openid email profile')

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'sso_configs'

    def __str__(self):
        return f'{self.org.slug} ({self.protocol})'


class OrgMembership(models.Model):
    ROLE_MEMBER = 'member'
    ROLE_ADMIN  = 'admin'
    ROLE_CHOICES = [(ROLE_MEMBER, 'Member'), (ROLE_ADMIN, 'Admin')]

    user           = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='org_memberships')
    org            = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='memberships')
    role           = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    sso_subject_id = models.CharField(max_length=500, blank=True,
                                      help_text='NameID (SAML) or sub (OIDC) from IdP')
    joined_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sso_org_memberships'
        unique_together = [('user', 'org')]

    def __str__(self):
        return f'{self.user} @ {self.org.slug} ({self.role})'


# =============================================================================
# Step-up verification — per-user policy preferences
# =============================================================================

class VerificationPreference(models.Model):
    """A user's step-up preference for one verification scope.

    Consulted by ``stapel_core.verification`` through the
    ``auth.verification.policy`` comm Function: ``enabled=False`` rows turn
    a ``default_on`` scope off, ``enabled=True`` rows turn an ``opt_in``
    scope on. ``strict`` endpoints ignore preferences entirely.
    """
    user       = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='verification_preferences')
    scope      = models.CharField(max_length=100)
    enabled    = models.BooleanField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'verification_preferences'
        unique_together = [('user', 'scope')]

    def __str__(self):
        return f'{self.user_id}:{self.scope} = {"on" if self.enabled else "off"}'
