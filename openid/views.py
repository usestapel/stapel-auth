"""OpenID Connect, JWKS discovery, and token introspection endpoint views."""

import logging

from django.urls import NoReverseMatch, reverse
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.views import APIView
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse
from stapel_core.django.openapi.schemas import StapelErrorSerializer

from stapel_auth.errors import ERR_401_TOKEN_INVALID

logger = logging.getLogger(__name__)


def _advertise(request, url_name):
    """Absolute URL of a mounted route — or None when it is not mounted.

    Discovery hands these URLs to EXTERNAL clients, so they have to be derived
    from the URLconf, never spelled out: ``reverse()`` picks up both the host's
    ``include()`` prefix and the ``v1/`` segment ``urls.py`` contributes, so
    the advertised path cannot drift away from the mounted one.

    Incident (2026-07): the literals here were the pre-library monolith's
    shapes (marketplace ``core/urls.py`` mounted these views directly under
    ``{URL_PREFIX}``) — ``/{URL_PREFIX}api/v1/auth/token/``,
    ``.../auth/token/refresh/``, ``.../auth/me/`` and
    ``/{URL_PREFIX}.well-known/jwks.json``. As a library the module mounts at
    ``/auth/api/v1/…`` with no second ``auth/`` segment, so every advertised
    endpoint 404'd for anyone who read the discovery document. The suite could
    not see it because it ran against the un-mounted inner urlconf
    (``tests/conftest_urls.py`` now fixes that).

    Returns None for a route the deployment left unmounted — the ``urls_v1``
    factories are feature-gated, and omitting a key beats advertising a 404.
    """
    try:
        return request.build_absolute_uri(reverse(url_name))
    except NoReverseMatch:
        return None


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
    a standard discovery endpoint. It is mounted at ``<mount>/.well-known/
    jwks.json`` (i.e. ``/auth/api/v1/.well-known/jwks.json`` in the canonical
    deployment) — NOT at the host root; a deployment that also publishes the
    static nginx copy at ``/.well-known/jwks.json`` points discovery at it via
    STAPEL_AUTH['JWKS_URI'].
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

        # Every endpoint below is derived from the URLconf (see _advertise) —
        # the incident these keys caused is documented there.
        #
        # jwks_uri is the one URL that may legitimately live outside Django:
        # some deployments serve the static jwks.json that
        # stapel_core.django.openapi.openid.generate_jwks_to_dir() writes for
        # nginx at the host root. That is the deployment's claim to make
        # (STAPEL_AUTH['JWKS_URI']), not a silent guess by this view; unset,
        # we advertise our own mounted route.
        from stapel_auth.conf import auth_settings

        jwks_uri = auth_settings.JWKS_URI
        endpoints = {
            "jwks_uri": (
                request.build_absolute_uri(jwks_uri)
                if jwks_uri
                else _advertise(request, "jwks")
            ),
            "token_endpoint": _advertise(request, "token_obtain_pair"),
            "token_refresh_endpoint": _advertise(request, "token_refresh"),
            "userinfo_endpoint": _advertise(request, "me"),
        }

        config = {
            "issuer": issuer,
            # Unmounted routes drop out rather than being advertised as 404s.
            **{key: url for key, url in endpoints.items() if url},
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
