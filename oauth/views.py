"""Views for OAuth account links (security-profile inventory): GET/POST/DELETE
/oauth/links/ — connect/disconnect additional OAuth provider accounts on an
already-authenticated user. Distinct from ``AuthViewSet.oauth_login`` (sign-in
with an OAuth provider), which lives in ``otp/views.py``.
"""

import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions
from rest_framework.viewsets import ViewSet
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse

from stapel_auth.errors import (
    ERR_400_LAST_AUTH_METHOD,
    ERR_400_OAUTH_FAILED,
    ERR_404_OAUTH_LINK_NOT_FOUND,
    ERR_409_OAUTH_ACCOUNT_LINKED_ELSEWHERE,
    ERR_409_OAUTH_ALREADY_LINKED,
)
from stapel_auth.oauth.serializers import (
    OAuthLinkRequestSerializer,
    OAuthLinksResponseSerializer,
)
from stapel_auth.oauth.services import OAuthLinkService
from stapel_auth.utils import SerializerSeamsMixin

logger = logging.getLogger(__name__)

_LINK_ERROR_RESPONSES = {
    "already_linked": (409, ERR_409_OAUTH_ALREADY_LINKED),
    "linked_elsewhere": (409, ERR_409_OAUTH_ACCOUNT_LINKED_ELSEWHERE),
    "failed": (400, ERR_400_OAUTH_FAILED),
}

_UNLINK_ERROR_RESPONSES = {
    "not_found": (404, ERR_404_OAUTH_LINK_NOT_FOUND),
    "last_method": (400, ERR_400_LAST_AUTH_METHOD),
}


class OAuthLinkViewSet(SerializerSeamsMixin, ViewSet):
    """Manage OAuth accounts connected to the current user."""

    permission_classes = [permissions.IsAuthenticated]

    # Overridable serializer seams (see SerializerSeamsMixin).
    list_response_serializer_class = OAuthLinksResponseSerializer
    link_request_serializer_class = OAuthLinkRequestSerializer
    link_response_serializer_class = OAuthLinksResponseSerializer

    @extend_schema(
        summary="List OAuth accounts connected to the current user",
        tags=["OAuth"],
        responses={200: OAuthLinksResponseSerializer},
    )
    def list_links(self, request):  # noqa: R007
        links = OAuthLinkService.list_links(request.user)
        return StapelResponse(
            self.get_list_response_serializer_class()({"links": links})
        )

    @extend_schema(
        summary="Link an additional OAuth provider account",
        tags=["OAuth"],
        request=OAuthLinkRequestSerializer,
        responses={
            200: OAuthLinksResponseSerializer,
            400: None,
            409: None,
        },
    )
    def link(self, request):  # noqa: R007
        ser = self.get_link_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        provider = ser.validated_data["provider"]
        access_token = ser.validated_data["access_token"]

        _row, error = OAuthLinkService.link(request.user, provider, access_token)
        if error:
            status_code, err = _LINK_ERROR_RESPONSES[error]
            return StapelErrorResponse(status_code, err)

        links = OAuthLinkService.list_links(request.user)
        return StapelResponse(
            self.get_link_response_serializer_class()({"links": links})
        )

    @extend_schema(
        summary="Unlink an OAuth provider account",
        tags=["OAuth"],
        responses={204: None, 400: None, 404: None},
    )
    def unlink(self, request, provider=None):  # noqa: R007
        result = OAuthLinkService.unlink(request.user, provider)
        if result != "ok":
            status_code, err = _UNLINK_ERROR_RESPONSES[result]
            return StapelErrorResponse(status_code, err)
        return StapelResponse(status=204)
