from django.contrib import admin
from .models import PhoneVerification, EmailVerification, ServiceAPIKey, RefreshTokenTracker, LoginAttempt, AuthenticatorChangeRequest


@admin.register(PhoneVerification)
class PhoneVerificationAdmin(admin.ModelAdmin):
    """Phone Verification admin"""
    
    list_display = ['phone', 'code', 'is_verified', 'created_at', 'expires_at', 'attempts']
    list_filter = ['is_verified', 'created_at']
    search_fields = ['phone']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    """Email Verification admin"""
    
    list_display = ['email', 'code', 'is_verified', 'created_at', 'expires_at', 'attempts']
    list_filter = ['is_verified', 'created_at']
    search_fields = ['email']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(ServiceAPIKey)
class ServiceAPIKeyAdmin(admin.ModelAdmin):
    """Service API Key admin"""
    
    list_display = ['name', 'key', 'is_active', 'created_at', 'last_used_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'key']
    ordering = ['-created_at']
    readonly_fields = ['key', 'created_at', 'last_used_at']
    
    def save_model(self, request, obj, form, change):
        if not change:  # Only set key on creation
            obj.key = ServiceAPIKey.generate_key()
        super().save_model(request, obj, form, change)


@admin.register(RefreshTokenTracker)
class RefreshTokenTrackerAdmin(admin.ModelAdmin):
    """Refresh Token Tracker admin"""
    
    list_display = ['user', 'created_at', 'expires_at', 'is_revoked', 'device_info']
    list_filter = ['is_revoked', 'created_at']
    search_fields = ['user__username', 'user__email', 'device_info']
    ordering = ['-created_at']
    readonly_fields = ['created_at']


@admin.register(AuthenticatorChangeRequest)
class AuthenticatorChangeRequestAdmin(admin.ModelAdmin):
    """Authenticator Change Request admin"""

    list_display = ['user', 'change_type', 'status', 'old_value', 'new_value', 'created_at', 'scheduled_at']
    list_filter = ['status', 'change_type']
    search_fields = ['old_value', 'new_value']
    ordering = ['-created_at']
    readonly_fields = ['id', 'change_token', 'created_at', 'completed_at', 'cancelled_at']


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Login Attempt admin"""
    
    list_display = ['identifier', 'attempt_type', 'ip_address', 'created_at']
    list_filter = ['attempt_type', 'created_at']
    search_fields = ['identifier', 'ip_address']
    ordering = ['-created_at']
    readonly_fields = ['created_at']