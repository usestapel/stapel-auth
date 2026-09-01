from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid

from stapel_core.access import access


@access.secret  # API key carrier (admin-suite AS-5)
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


@access.secret  # raw refresh token carrier (admin-suite AS-5)
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


@access.secret  # TOTP shared secret + hashed backup codes (admin-suite AS-5)
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
    TOTP = 'totp', 'TOTP'


class AuthenticatorChangeStatus(models.TextChoices):
    PENDING = 'pending', 'Pending'
    COMPLETED = 'completed', 'Completed'
    CANCELLED = 'cancelled', 'Cancelled'
    EXPIRED = 'expired', 'Expired'


@access.ops  # change-flow workflow/audit record (admin-suite AS-5); the
# live change_token is masked explicitly on the admin (see admin/__init__.py)
class AuthenticatorChangeRequest(models.Model):
    """
    Tracks pending authenticator (phone/email/TOTP) change requests.
    Supports both instant (double OTP / TOTP proof-of-possession) and
    delayed (14-day) flows.

    TOTP rows are a "disable only" flavour of the delayed flow (see
    ``otp.services.AuthenticatorChangeService.initiate_delayed_totp``): a
    user who lost their authenticator has no address to prove — the
    request just schedules removal of the device (with the same
    notify/cancel window), after which they re-enroll via the normal
    instant ``setup``/``confirm_setup`` pair. ``old_value`` is unused
    (blank) and ``new_value`` holds an opaque, per-request unique marker
    (never displayed) purely to satisfy the ``unique_pending_reservation``
    constraint below — TOTP has no "new address" to reserve.
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


@access.ops  # security audit log (admin-suite AS-5)
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
    PASSKEY_RENAMED     = 'passkey_renamed'
    OAUTH_LOGIN         = 'oauth_login'
    QR_LOGIN            = 'qr_login'
    SSO_LOGIN           = 'sso_login'
    TOTP_FAILED         = 'totp_failed'
    CAPTCHA_FAILED      = 'captcha_failed'


@access.ops  # audit log (admin-suite AS-5)
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
# OAuth account links (security-profile inventory: additional linked accounts
# beyond the one a user registered/logged in with — see oauth/services.py
# OAuthLinkService and GET/POST/DELETE /oauth/links/)
# =============================================================================

class LinkedOAuthAccount(models.Model):
    """An additional OAuth provider account linked to an existing user.

    Deliberately separate from ``User.oauth_provider``/``oauth_id`` (the
    provider a user originally registered/logged in with, resolved by
    ``AuthViewSet._resolve_oauth_user``): that pair is immutable through this
    model on purpose — unlinking it would change how the account authenticates
    at all, which is a bigger decision than "manage my connected accounts" and
    is out of scope for this endpoint. A row here is always a *secondary*
    link a signed-in user attached from their security settings page.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='linked_oauth_accounts',
        help_text='The account this link belongs to.',
    )
    provider = models.CharField(max_length=50, help_text='OAuth provider id, e.g. google, github.')
    provider_user_id = models.CharField(
        max_length=255,
        help_text="The provider's own user id — keyed on this (not email) for account-takeover-safe uniqueness.",
    )
    email = models.EmailField(
        blank=True, null=True, help_text='Email reported by the provider, if any (display only).',
    )
    display_name = models.CharField(
        max_length=255, blank=True, help_text='Provider display name/username, if any (display only).',
    )
    linked_at = models.DateTimeField(auto_now_add=True, help_text='When this account was linked.')

    class Meta:
        db_table = 'linked_oauth_accounts'
        ordering = ['-linked_at']
        constraints = [
            # One link per provider per user (re-linking the same provider updates the existing row).
            models.UniqueConstraint(fields=['user', 'provider'], name='unique_provider_per_user'),
            # The same external provider account can't be linked to two different users.
            models.UniqueConstraint(fields=['provider', 'provider_user_id'], name='unique_provider_account'),
        ]

    def __str__(self):
        return f'{self.user_id} ↔ {self.provider}'


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


@access.secret  # carries oidc_client_secret (admin-suite AS-5)
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
    # URLField defaults to max_length=200 — too short for real IdP endpoints
    # (Okta/Azure AD SSO URLs routinely carry long encoded query params).
    # Widened to 500 to match sibling saml_entity_id/oidc_client_secret.
    saml_entity_id     = models.CharField(max_length=500, blank=True, help_text='IdP entity ID / issuer')
    saml_sso_url       = models.URLField(max_length=500, blank=True, help_text='IdP SSO URL (redirect binding)')
    saml_slo_url       = models.URLField(max_length=500, blank=True, help_text='IdP SLO URL (optional)')
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
    oidc_discovery_url = models.URLField(max_length=500, blank=True, help_text='.well-known/openid-configuration URL')
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
# Staff roles — assignments (admin-suite AS-2)
# =============================================================================

@access(category="business", view="high", add="high", change="high", delete="high")
class StaffRoleAssignment(models.Model):
    """One staff role held by one user (admin-suite AS-2, invariant A2).

    Role *definitions* (name → clearance profile) are deploy config — the
    ``STAPEL_ACCESS["ROLES"]`` merge-registry of ``stapel_core.access`` (AS-1).
    This table stores only *assignments* (user → role name), and it exists in
    the auth service alone: auth is the single writer, consumer services are
    read-only recipients of the materialized ``staff_roles`` JWT claim.

    ``role_name`` is a plain string validated against the settings registry at
    assignment time — deliberately NOT a FK into a database catalog, so that a
    runtime admin can never edit the clearance profile a name resolves to
    (MAC stays MAC; see admin-suite §3.3).

    Rows are immutable: changing a user's roles is revoke + assign, each step
    audited by its own outbox event (``staff.role.assigned`` / ``.revoked``).
    Access declaration: managing assignments is itself a HIGH-clearance
    operation (admin-suite §3.3 — "gated behind HIGH clearance").
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='staff_role_assignments',
    )
    role_name = models.CharField(max_length=100)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='staff_roles_granted',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'staff_role_assignments'
        ordering = ['role_name']
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'role_name'],
                name='unique_staff_role_per_user',
            ),
        ]

    def __str__(self):
        return f'{self.user} → {self.role_name}'


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


# =============================================================================
# Account merges — the ledger behind ``user.merged``
# =============================================================================

class MergeSource(models.TextChoices):
    """Which proof identified the survivor.

    ``user.merged`` carries ``reason="anonymous_promotion"`` for every path,
    which is true and tells an operator nothing. This is the distinction that
    matters when a merge is questioned later: an OAuth identity match is a
    much stronger claim than an email that a provider says it verified.
    """

    EMAIL_OTP = 'email_otp', 'Email OTP'
    PHONE_OTP = 'phone_otp', 'Phone OTP'
    OAUTH_IDENTITY = 'oauth_identity', 'OAuth provider identity'
    OAUTH_EMAIL = 'oauth_email', 'OAuth verified email'
    UNKNOWN = 'unknown', 'Unknown'


@access.ops  # merge ledger (admin-suite AS-5)
class UserMerge(models.Model):
    """One guest account folded into one surviving account.

    **Why a table and not just the event.** ``user.merged`` is emitted in the
    merge's own transaction and is the instruction consumers act on. But an
    event is a delivery, not a record: a stream has retention, a consumer
    deployed after the merge never saw it, a consumer whose handler was
    broken for a week cannot ask what it missed, and a support question six
    months later ("why does this survivor own that guest's listing?") has
    nothing to read. The guest row itself is deleted by then, so the mapping
    exists nowhere else in this service.

    So the mapping is written in the SAME transaction as the merge and the
    emit. Either all three commit or none does — a ledger that could
    disagree with the event would be worse than no ledger, because it would
    be trusted.

    **Not foreign keys, deliberately.** ``merged_id`` names a row that is
    deleted microseconds later, so an FK is impossible; ``survivor_id`` names
    a row that may be erased on a GDPR request, and an FK would either block
    that erasure or null the mapping out. The whole point of this table is to
    outlive both. Ids are plain UUIDs, as they are for every cross-service
    reference in the fleet.

    **Idempotent by construction.** ``merged_id`` is unique: an id can be
    absorbed once, because it stops existing. A redelivered or retried merge
    hits the constraint and updates nothing rather than writing a second,
    contradictory row.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    merged_id = models.UUIDField(
        unique=True,
        db_index=True,
        help_text='The guest account that was absorbed and then deleted.',
    )
    survivor_id = models.UUIDField(
        db_index=True,
        help_text='The account that survived and now owns the guest\'s rows.',
    )
    merged_at = models.DateTimeField(default=timezone.now, db_index=True)
    source = models.CharField(
        max_length=32,
        choices=MergeSource,
        default=MergeSource.UNKNOWN,
        help_text='Which proof identified the survivor.',
    )

    class Meta:
        db_table = 'auth_user_merge'
        ordering = ['-merged_at']
        indexes = [
            models.Index(fields=['survivor_id', 'merged_at']),
        ]

    def __str__(self):
        return f'{self.merged_id} → {self.survivor_id} ({self.source})'

    # The depth cap is not a guess about how long chains get — a chain of
    # more than a handful is already a bug — it is a refusal to spin forever
    # on a cycle that a bad backfill could write. Reached, it returns the
    # last id it walked to, which is the best answer available.
    RESOLVE_MAX_DEPTH = 16

    @classmethod
    def resolve(cls, user_id):
        """Follow the merge chain: the account *user_id* is reachable as today.

        A guest may be merged into an account that is itself later merged
        into a third. A consumer reconciling after downtime asks about the id
        it holds and needs the END of that chain, not one hop — one hop hands
        it an id that also no longer signs in, and it would have to know to
        ask again.

        Returns *user_id* unchanged when it was never merged, which makes
        this safe to call on every id rather than only on ones known to be
        stale.
        """
        seen = {str(user_id)}
        current = user_id
        for _ in range(cls.RESOLVE_MAX_DEPTH):
            row = cls.objects.filter(merged_id=current).values_list(
                'survivor_id', flat=True
            ).first()
            if row is None:
                return current
            if str(row) in seen:  # a cycle; stop rather than spin
                return current
            seen.add(str(row))
            current = row
        return current

    @classmethod
    def absorbed_by(cls, survivor_id):
        """Every id that resolves to *survivor_id*, including through chains.

        The reconciliation direction: "which old ids do rows I still hold
        point at?" Walks the tree of merges rooted at the survivor, so a
        guest absorbed two hops back is included.
        """
        found = []
        frontier = [survivor_id]
        seen = {str(survivor_id)}
        for _ in range(cls.RESOLVE_MAX_DEPTH):
            if not frontier:
                break
            rows = list(
                cls.objects.filter(survivor_id__in=frontier).values_list(
                    'merged_id', flat=True
                )
            )
            frontier = []
            for merged_id in rows:
                if str(merged_id) in seen:
                    continue
                seen.add(str(merged_id))
                found.append(merged_id)
                frontier.append(merged_id)
        return found
