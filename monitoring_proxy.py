"""
Monitoring auth check for nginx auth_request.

Returns 200 with user headers if user is staff/superuser.
Returns 401 if not authenticated or not authorized.
Used by nginx auth_request directive.
"""
from django.http import HttpResponse
from django.views import View


class MonitoringAuthCheckView(View):
    """
    Auth check endpoint for nginx auth_request.

    nginx will call this endpoint before proxying to Grafana/Prometheus.
    Returns 200 with X-WEBAUTH-* headers if authorized.
    Returns 401 if not authenticated or not staff/superuser.
    """

    def get(self, request):
        # Check authentication
        if not request.user.is_authenticated:
            return HttpResponse(status=401)

        # Check permission (staff or superuser)
        if not (request.user.is_staff or request.user.is_superuser):
            return HttpResponse(status=403)

        # Return 200 with auth headers for nginx to forward
        response = HttpResponse(status=200)
        response["X-WEBAUTH-USER"] = str(request.user.id)
        response["X-WEBAUTH-EMAIL"] = request.user.email
        response["X-WEBAUTH-NAME"] = request.user.get_full_name() or request.user.email
        response["X-WEBAUTH-ROLE"] = "Admin" if request.user.is_superuser else "Editor"
        return response
