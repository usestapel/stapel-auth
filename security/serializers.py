"""Serializers for the security sub-package (security status, audit log)."""
from stapel_core.django.api.serializers import StapelDataclassSerializer
from rest_framework import serializers

from stapel_auth.security.dto import (
    SecurityStatusPassword,
    SecurityStatusTOTP,
    SecurityStatusContact,
    SecurityStatusOAuth,
    SecurityStatusSessions,
    SecurityStatusPasskeys,
    SecurityStatusResponse,
)


# =============================================================================
# Security Status serializers
# =============================================================================

class SecurityStatusPasswordSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusPassword


class SecurityStatusTOTPSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusTOTP


class SecurityStatusContactSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusContact


class SecurityStatusOAuthSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusOAuth


class SecurityStatusSessionsSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusSessions


class SecurityStatusPasskeysSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusPasskeys


class SecurityStatusResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusResponse


# =============================================================================
# Audit Log serializer (originally inline in security_views.py)
# =============================================================================

class AuditLogEntrySerializer(serializers.Serializer):
    id          = serializers.CharField()
    event_type  = serializers.CharField()
    ip_address  = serializers.CharField(allow_null=True)
    user_agent  = serializers.CharField()
    metadata    = serializers.DictField()
    created_at  = serializers.DateTimeField()


class AuditLogPageSerializer(serializers.Serializer):
    results = AuditLogEntrySerializer(many=True)
    count   = serializers.IntegerField()
    next    = serializers.IntegerField(allow_null=True)


class AuditLogFilterSerializer(serializers.Serializer):
    event_type = serializers.CharField(required=False)
    date_from  = serializers.DateField(required=False)
    date_to    = serializers.DateField(required=False)
    page       = serializers.IntegerField(required=False, min_value=1, default=1)


class AdminAuditLogFilterSerializer(serializers.Serializer):
    user_id    = serializers.UUIDField(required=False)
    event_type = serializers.CharField(required=False)
    date_from  = serializers.DateField(required=False)
    date_to    = serializers.DateField(required=False)
    page       = serializers.IntegerField(required=False, min_value=1, default=1)
