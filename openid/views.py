"""OpenID Connect, JWKS discovery, and token introspection endpoint views."""

import logging

from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.views import APIView
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse
from stapel_core.django.openapi.schemas import StapelErrorSerializer

from stapel_auth.errors import ERR_401_TOKEN_INVALID

logger = logging.getLogger(__name__)


class TokenIntrospectRequestSerializer(serializers.Serializer):
    """RFC 7662 introspection request body."""

    token = serializers.CharField(help_text="The JWT access token to introspect.")


class TokenIntrospectResponseSerializer(serializers.Serializer):
    """RFC 7662 introspection response.

    ``active`` is always present; the claim fields are only populated when the
    token is valid.
    """

    active = serializers.BooleanField(
        help_text="Whether the token is currently valid."
    )
    sub = serializers.CharField(
        required=False, help_text="Subject (user_id) claim."
    )
    username = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    scope = serializers.CharField(required=False)
    exp = serializers.IntegerField(required=False, help_text="Expiry (unix ts).")
    iat = serializers.IntegerField(required=False, help_text="Issued-at (unix ts).")
    iss = serializers.CharField(required=False, help_text="Issuer.")
    token_type = serializers.CharField(required=False)


class JWKSView(viewsets.GenericViewSet):
    """
    JSON Web Key Set (JWKS) endpoint.

    Provides the public key(s) for JWT verification in standard JWKS format.
    This endpoint is used by other services and external clients to verify tokens
    issued by this auth service.

    For HS256 (symmetric): Returns algorithm info but no key (key cannot be shared).
    For RS256 (asymmetric): Returns the public key in JWK format.

    Note: This endpoint is excluded from Swagger/OpenAPI documentation as it's
    a standard discovery endpoint accessed directly via /.well-known/jwks.json
    """

    permission_classes = [permissions.AllowAny]
    schema = None  # Exclude from OpenAPI schema generation

    @action(detail=False, methods=["get"], url_path="")
    def jwks(self, request):  # noqa: R003
        """Return JWKS for token verification."""
        from stapel_core.django.jwt.provider import jwt_provider

        config = jwt_provider.config
        algorithm = config.algorithm
        issuer = config.issuer

        if algorithm == "RS256":
            # RS256 mode - return public key in JWKS format
            try:
                jwks = jwt_provider.get_jwks()

                if jwks:
                    return StapelResponse(jwks, status=status.HTTP_200_OK)
                else:
                    return StapelResponse(  # noqa: R006
                        {"keys": [], "error": "Public key not available"},
                        status=status.HTTP_200_OK,
                    )
            except Exception as e:
                logger.error(f"Failed to generate JWKS: {e}")
                return StapelResponse(  # noqa: R006
                    {"keys": [], "error": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            # HS256 mode - cannot share symmetric keyk
            return StapelResponse(  # noqa: R006
                {
                    "keys": [],
                    "_info": {
                        "algorithm": algorithm,
                        "issuer": issuer,
                        "note": "HS256 uses symmetric key which cannot be shared via JWKS. "
                        "Use the same JWT_SECRET_KEY configured in all services.",
                    },
                },
                status=status.HTTP_200_OK,
            )


class OpenIDConfigurationView(viewsets.GenericViewSet):
    """
    OpenID Connect Discovery endpoint.

    Provides the OpenID Connect configuration for token verification.
    This is the standard .well-known/openid-configuration endpoint.

    Note: This endpoint is excluded from Swagger/OpenAPI documentation as it's
    a standard discovery endpoint accessed directly via /.well-known/openid-configuration
    """

    permission_classes = [permissions.AllowAny]
    schema = None  # Exclude from OpenAPI schema generation

    @action(detail=False, methods=["get"], url_path="")
    def openid_configuration(self, request):  # noqa: R003
        """Return OpenID Connect configuration."""
        from stapel_core.django.jwt.provider import jwt_provider

        config = jwt_provider.config
        algorithm = config.algorithm
        issuer = config.issuer

        # Build base URL from request
        scheme = request.scheme
        host = request.get_host()
        base_url = f"{scheme}://{host}"

        url_prefix = getattr(settings, "URL_PREFIX", "")

        config = {
            "issuer": issuer,
            "jwks_uri": f"{base_url}/{url_prefix}.well-known/jwks.json",
            "token_endpoint": f"{base_url}/{url_prefix}api/v1/auth/token/",
            "token_refresh_endpoint": f"{base_url}/{url_prefix}api/v1/auth/token/refresh/",
            "userinfo_endpoint": f"{base_url}/{url_prefix}api/v1/auth/me/",
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [algorithm],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "claims_supported": [
                "sub",
                "user_id",
                "email",
                "username",
                "iss",
                "exp",
                "iat",
                "jti",
                "token_type",
                "auth_type",
                "is_anonymous",
                "is_staff",
                "is_superuser",
            ],
        }

        return StapelResponse(config, status=status.HTTP_200_OK)


class TokenIntrospectView(APIView):
    """RFC 7662 token introspection endpoint.

    For use by trusted internal services only (requires service API key).
    POST body: ``token=<jwt_string>`` (application/x-www-form-urlencoded or JSON).

    Returns ``{"active": false}`` for invalid/expired tokens — not 401.
    """

    permission_classes = []
    authentication_classes = []

    @extend_schema(
        summary="RFC 7662 token introspection (service-to-service)",
        description=(
            "Introspect a JWT. Requires a service API key. Returns "
            "`{\"active\": false}` for invalid/expired tokens (never 401 for those). "
            "A 401 is only returned when the caller's service API key is missing/invalid."
        ),
        request=TokenIntrospectRequestSerializer,
        responses={
            200: TokenIntrospectResponseSerializer,
            401: StapelErrorSerializer,
        },
        tags=["OpenID"],
    )
    def post(self, request):  # noqa: R007
        from stapel_auth.permissions import IsServiceAPIKey

        if not IsServiceAPIKey().has_permission(request, self):
            return StapelErrorResponse(401, ERR_401_TOKEN_INVALID)

        token = request.data.get("token", "").strip()
        if not token:
            return StapelResponse({"active": False})  # noqa: R006

        from stapel_core.django.jwt.provider import jwt_provider

        payload = jwt_provider.validate_token(token)
        if not payload:
            return StapelResponse({"active": False})  # noqa: R006

        return StapelResponse(  # noqa: R006
            {  # noqa: R006
                "active": True,
                "sub": payload.get("user_id"),
                "username": payload.get("username"),
                "email": payload.get("email"),
                "scope": payload.get("scope", ""),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "iss": payload.get("iss"),
                "token_type": payload.get("token_type", "access"),
            }
        )
