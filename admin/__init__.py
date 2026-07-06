"""Django admin registrations for stapel-auth models.

Historically these ``ModelAdmin`` classes lived in a top-level ``admin.py``
next to this package. Because ``package-dir`` maps both ``admin.py`` and this
``admin/`` package to the same import path, the package always won: Django's
admin autodiscover imports ``stapel_auth.admin`` and reached this (previously
empty) package, so the registrations in ``admin.py`` never loaded in
production. Merging them here makes the models appear in the Django admin as
originally intended. See CHANGELOG (Fixed).
"""
from django import forms
from django.contrib import admin

from stapel_core.django.admin.base import StapelModelAdmin

from stapel_auth.models import (
    AuthAuditLog,
    AuthenticatorChangeRequest,
    EmailVerification,
    LoginAttempt,
    PhoneVerification,
    RefreshTokenTracker,
    ServiceAPIKey,
    SSOConfig,
    StaffRoleAssignment,
    TOTPDevice,
)


@admin.register(PhoneVerification)
class PhoneVerificationAdmin(StapelModelAdmin):
    """Phone Verification admin (ops journal — TTL-expiring OTP junk, admin-suite AS-5)"""

    list_display = ['phone', 'code', 'is_verified', 'created_at', 'expires_at', 'attempts']
    list_filter = ['is_verified', 'created_at']
    search_fields = ['phone']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(EmailVerification)
class EmailVerificationAdmin(StapelModelAdmin):
    """Email Verification admin (ops journal — TTL-expiring OTP junk, admin-suite AS-5)"""

    list_display = ['email', 'code', 'is_verified', 'created_at', 'expires_at', 'attempts']
    list_filter = ['is_verified', 'created_at']
    search_fields = ['email']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(ServiceAPIKey)
class ServiceAPIKeyAdmin(StapelModelAdmin):
    """Service API Key admin (secret carrier — superuser-only, `key` masked
    via pattern auto-detection, admin-suite AS-5)"""

    list_display = ['name', 'key', 'is_active', 'created_at', 'last_used_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'key']
    ordering = ['-created_at']
    # 'key' itself is NOT listed here: the secret-masking mixin makes the
    # masked placeholder read-only on its own, and a raw 'key' entry here
    # would render the real value in a second, unmasked field (admin-suite AS-5).
    readonly_fields = ['created_at', 'last_used_at']

    def save_model(self, request, obj, form, change):
        if not change:  # Only set key on creation
            obj.key = ServiceAPIKey.generate_key()
        super().save_model(request, obj, form, change)


@admin.register(RefreshTokenTracker)
class RefreshTokenTrackerAdmin(StapelModelAdmin):
    """Refresh Token Tracker admin (secret carrier — superuser-only, `token`
    masked via pattern auto-detection, admin-suite AS-5)"""

    list_display = ['user', 'created_at', 'expires_at', 'is_revoked', 'device_info']
    list_filter = ['is_revoked', 'created_at']
    search_fields = ['user__username', 'user__email', 'device_info']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(AuthenticatorChangeRequest)
class AuthenticatorChangeRequestAdmin(StapelModelAdmin):
    """Authenticator Change Request admin (ops journal, admin-suite AS-5).

    ``change_token`` links the instant-flow verify-old -> request-new ->
    verify-new steps, so it is a live bearer credential for the pending
    change even though the row otherwise reads like a workflow/audit log —
    pinned explicitly since the field name doesn't match the secret-pattern
    auto-detector (the "session key on an ops journal" shape).
    """

    secret_fields = ('change_token',)
    list_display = ['user', 'change_type', 'status', 'old_value', 'new_value', 'created_at', 'scheduled_at']
    list_filter = ['status', 'change_type']
    search_fields = ['old_value', 'new_value']
    ordering = ['-created_at']
    # 'change_token' is NOT listed here: for an `ops` category admin the
    # mixin already makes every concrete field read-only, swapping masked
    # fields for their placeholder — but only if the raw name isn't already
    # present in readonly_fields (admin-suite AS-5).
    readonly_fields = ['id', 'created_at', 'completed_at', 'cancelled_at']


@admin.register(LoginAttempt)
class LoginAttemptAdmin(StapelModelAdmin):
    """Login Attempt admin (ops journal — security audit log, admin-suite AS-5)"""

    list_display = ['identifier', 'attempt_type', 'ip_address', 'created_at']
    list_filter = ['attempt_type', 'created_at']
    search_fields = ['identifier', 'ip_address']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(AuthAuditLog)
class AuthAuditLogAdmin(StapelModelAdmin):
    """Auth Audit Log admin (ops journal, admin-suite AS-5 — no prior admin
    registration existed for this model)"""

    list_display = ['user', 'event_type', 'ip_address', 'created_at']
    list_filter = ['event_type', 'created_at']
    search_fields = ['user__username', 'user__email', 'ip_address']
    ordering = ['-created_at']


@admin.register(TOTPDevice)
class TOTPDeviceAdmin(StapelModelAdmin):
    """TOTP Device admin (secret carrier, admin-suite AS-5 — no prior admin
    registration existed for this model).

    ``secret`` (the raw shared secret) would be pattern-auto-detected, but
    ``backup_codes`` would not, so both are pinned explicitly.
    """

    secret_fields = ('secret', 'backup_codes')
    list_display = ['user', 'is_active', 'created_at', 'confirmed_at']
    list_filter = ['is_active']
    search_fields = ['user__username', 'user__email']
    ordering = ['-created_at']


@admin.register(SSOConfig)
class SSOConfigAdmin(StapelModelAdmin):
    """SSO Config admin (secret carrier — `oidc_client_secret` masked via
    pattern auto-detection, admin-suite AS-5 — no prior admin registration
    existed for this model)"""

    list_display = ['org', 'protocol', 'is_active', 'updated_at']
    list_filter = ['protocol', 'is_active']
    search_fields = ['org__name', 'org__slug']
    ordering = ['org__name']


class StaffRoleAssignmentForm(forms.ModelForm):
    """Validates the role name against the STAPEL_ACCESS['ROLES'] registry
    and the target against staff status — same rules as the service layer,
    surfaced as form errors instead of a 500."""

    class Meta:
        model = StaffRoleAssignment
        fields = ['user', 'role_name']

    def clean_role_name(self):
        from stapel_core.access import effective_roles

        role_name = self.cleaned_data['role_name']
        registry = effective_roles()
        if role_name not in registry:
            raise forms.ValidationError(
                'Unknown staff role %(role)r. Known roles: %(known)s — define new '
                'ones in the STAPEL_ACCESS["ROLES"] deploy config.',
                params={'role': role_name, 'known': ', '.join(sorted(registry))},
            )
        return role_name

    def clean_user(self):
        user = self.cleaned_data['user']
        if not (user.is_staff or user.is_superuser):
            raise forms.ValidationError(
                'Staff roles can only be assigned to staff accounts — '
                'make the user staff first.'
            )
        return user


@admin.register(StaffRoleAssignment)
class StaffRoleAssignmentAdmin(admin.ModelAdmin):
    """Staff role assignments (admin-suite AS-2).

    Writes are routed through ``stapel_auth.staff_roles`` services so the
    ``staff.role.assigned`` / ``staff.role.revoked`` audit events are never
    skipped (A2/S6). Rows are immutable — change = revoke + assign — so the
    change view is disabled. The model is declared all-HIGH via ``@access``:
    once the AS-1 mandate backends are installed, only clearance-HIGH staff
    (or superusers) see this admin at all.
    """

    form = StaffRoleAssignmentForm
    list_display = ['user', 'role_name', 'assigned_by', 'created_at']
    list_filter = ['role_name', 'created_at']
    search_fields = ['user__username', 'user__email', 'role_name']
    ordering = ['user_id', 'role_name']
    raw_id_fields = ['user']
    readonly_fields = ['assigned_by', 'created_at']

    def has_change_permission(self, request, obj=None):
        return False  # immutable rows: change = revoke + assign

    def save_model(self, request, obj, form, change):
        from stapel_auth.staff_roles import assign_staff_role

        # Route through the service (validated by the form already) so the
        # outbox audit event is emitted with the acting admin as actor.
        assignment, _created = assign_staff_role(
            obj.user, obj.role_name, assigned_by=request.user
        )
        obj.pk = assignment.pk

    def delete_model(self, request, obj):
        from stapel_auth.staff_roles import revoke_staff_role

        revoke_staff_role(obj.user, obj.role_name, revoked_by=request.user)

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            self.delete_model(request, obj)
