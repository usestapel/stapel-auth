from rest_framework import permissions
from django.utils import timezone
from .models import ServiceAPIKey
import logging

logger = logging.getLogger(__name__)


class IsServiceAPIKey(permissions.BasePermission):
    """
    Permission class to check if request has valid service API key
    """
    
    def has_permission(self, request, view):
        # Check for API key in header
        api_key = request.headers.get('x-api-key')
        
        if not api_key:
            return False
        
        try:
            service_key = ServiceAPIKey.objects.get(key=api_key, is_active=True)
            
            # Update last used timestamp
            service_key.last_used_at = timezone.now()
            service_key.save(update_fields=['last_used_at'])
            
            # Attach service to request for later use
            request.service = service_key
            
            return True
        except ServiceAPIKey.DoesNotExist:
            logger.warning(f"Invalid API key attempt: {api_key[:10]}...")
            return False


class IsInternalService(permissions.BasePermission):
    """
    Permission class for internal service-to-service communication
    """
    
    def has_permission(self, request, view):
        from django.conf import settings
        
        # Check for internal service key
        internal_key = request.headers.get('x-internal-service-key')
        
        if not internal_key:
            return False
        
        if internal_key == settings.INTERNAL_SERVICE_KEY:
            return True
        
        logger.warning("Invalid internal service key attempt")
        return False


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner
        return obj.user == request.user