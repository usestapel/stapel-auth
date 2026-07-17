"""Step-up verification endpoints: challenge info / initiate / complete.

Serves the client cycle of ``stapel_core.verification`` (see
flows-and-verification.md §2 and the ``auth.step_up_verification`` flow):

    1. a protected endpoint answers 403 with a ``verification`` envelope;
    2. GET  /verification/{challenge_id}/           — factors to offer;
    3. POST /verification/{challenge_id}/initiate/  — kick a factor off;
    4. POST /verification/{challenge_id}/complete/  — submit the proof;
    5. retry the original request (grant is server-side; stateless clients
       resend the returned X-Verification-Token header).

All endpoints are owner-bound: a challenge created for another user is
indistinguishable from a missing one (404).
"""
import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, viewsets
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse
from stapel_core.django.openapi.schemas import StapelErrorSerializer
from stapel_core.verification import errors as _verification_errors  # noqa: F401 — registers error keys
from stapel_core.verification import factor_registry
from stapel_core.verification.grants import (
    ERR_400_VERIFICATION_FACTOR,
    ERR_400_VERIFICATION_FAILED,
    ERR_404_VERIFICATION_CHALLENGE,
    ERR_423_VERIFICATION_LOCKED,
    complete_challenge,
    get_challenge,
    record_failed_attempt,
)

from stapel_core.verification import requires_verification
from stapel_core.verification.decorators import VERIFICATION_ATTR
from stapel_core.verification.policy import invalidate_policy_cache

from stapel_auth.utils import SerializerSeamsMixin
from stapel_auth.verification.serializers import (
    VerificationChallengeInfoResponseSerializer,
    VerificationCompleteResponseSerializer,
    VerificationCompleteSerializer,
    VerificationInitiateResponseSerializer,
    VerificationInitiateSerializer,
    VerificationPreferenceRowSerializer,
    VerificationPreferenceSerializer,
    VerificationPreferencesResponseSerializer,
)

logger = logging.getLogger(__name__)


class VerificationViewSet(SerializerSeamsMixin, viewsets.ViewSet):
    """Challenge-scoped verification endpoints, owner-bound."""

    permission_classes = [permissions.IsAuthenticated]

    # Overridable serializer seams (see SerializerSeamsMixin).
    info_response_serializer_class = VerificationChallengeInfoResponseSerializer
    initiate_request_serializer_class = VerificationInitiateSerializer
    initiate_response_serializer_class = VerificationInitiateResponseSerializer
    complete_request_serializer_class = VerificationCompleteSerializer
    complete_response_serializer_class = VerificationCompleteResponseSerializer

    # ── helpers ──────────────────────────────────────────────────────────

    def _get_owned_challenge(self, request, challenge_id):
        """The challenge, or None when missing/expired/foreign.

        A foreign challenge deliberately yields the same 404 as a missing
        one — existence of other users' challenges must not be observable.
        """
        challenge = get_challenge(challenge_id)
        if not challenge or challenge.get("user_id") != str(request.user.pk):
            return None
        return challenge

    def _resolve_factor(self, request, challenge, factor_id):
        """The factor instance, or None when it can't serve this challenge."""
        if factor_id not in challenge.get("factors", []):
            return None
        try:
            factor = factor_registry.get(factor_id)
        except KeyError:
            logger.warning("verification factor %r not registered", factor_id)
            return None
        if not factor.available_for(request.user):
            return None
        return factor

    # ── endpoints ────────────────────────────────────────────────────────

    @extend_schema(
        description=(
            "Step-up verification challenge info. Returns the challenge's scope "
            "and its factor list filtered to the factors this user can actually "
            "complete — build the factor picker UI from it. 404 for a missing, "
            "expired or another user's challenge."
        ),
        responses={
            200: VerificationChallengeInfoResponseSerializer,
            404: StapelErrorSerializer,
        },
    )
    def info(self, request, challenge_id=None):
        from stapel_auth.verification.dto import VerificationChallengeInfoResponse

        challenge = self._get_owned_challenge(request, challenge_id)
        if challenge is None:
            return StapelErrorResponse(404, ERR_404_VERIFICATION_CHALLENGE)

        available = factor_registry.available_for(
            request.user, challenge.get("factors", [])
        )
        dto = VerificationChallengeInfoResponse(
            challenge_id=challenge["challenge_id"],
            scope=challenge["scope"],
            factors=available,
            expires_at=int(challenge["expires_at"]),
        )
        return StapelResponse(self.get_info_response_serializer_class()(dto))

    @extend_schema(
        description=(
            "Initiate a verification factor for the challenge: sends the one-time "
            "code (otp_email/otp_phone) or produces WebAuthn request options "
            "(passkey; totp has nothing to initiate). Returns factor-specific "
            "client data — masked destination or the WebAuthn options with the "
            "ceremony session_key. The factor must be in the challenge's list "
            "and available to the user."
        ),
        request=VerificationInitiateSerializer,
        responses={
            200: VerificationInitiateResponseSerializer,
            400: StapelErrorSerializer,
            404: StapelErrorSerializer,
        },
    )
    def initiate(self, request, challenge_id=None):
        from stapel_auth.verification.dto import VerificationInitiateResponse
        from stapel_auth.verification_factors import FactorInitiationError

        challenge = self._get_owned_challenge(request, challenge_id)
        if challenge is None:
            return StapelErrorResponse(404, ERR_404_VERIFICATION_CHALLENGE)

        serializer = self.get_initiate_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        factor_id = serializer.validated_data["factor"]

        factor = self._resolve_factor(request, challenge, factor_id)
        if factor is None:
            return StapelErrorResponse(400, ERR_400_VERIFICATION_FACTOR)

        try:
            data = factor.initiate(request.user, challenge) or {}
        except FactorInitiationError:
            return StapelErrorResponse(400, ERR_400_VERIFICATION_FAILED)

        dto = VerificationInitiateResponse(factor=factor_id, data=data)
        return StapelResponse(self.get_initiate_response_serializer_class()(dto))

    @extend_schema(
        description=(
            "Complete the challenge with the factor's proof (code / backup_code / "
            "passkey assertion). On success the server-side grant for the "
            "challenge's scope is written and a stateless verification_token is "
            "returned — retry the original request (optionally with the "
            "X-Verification-Token header). On failure: 400 while attempts "
            "remain, 423 once the challenge is invalidated by too many failures."
        ),
        request=VerificationCompleteSerializer,
        responses={
            200: VerificationCompleteResponseSerializer,
            400: StapelErrorSerializer,
            404: StapelErrorSerializer,
            423: StapelErrorSerializer,
        },
    )
    def complete(self, request, challenge_id=None):
        from stapel_auth.verification.dto import VerificationCompleteResponse

        challenge = self._get_owned_challenge(request, challenge_id)
        if challenge is None:
            return StapelErrorResponse(404, ERR_404_VERIFICATION_CHALLENGE)

        serializer = self.get_complete_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        factor_id = serializer.validated_data["factor"]

        factor = self._resolve_factor(request, challenge, factor_id)
        if factor is None:
            return StapelErrorResponse(400, ERR_400_VERIFICATION_FACTOR)

        payload = {k: v for k, v in serializer.validated_data.items() if k != "factor"}
        try:
            verified = bool(factor.verify(request.user, challenge, payload))
        except Exception:
            logger.exception(
                "verification factor %s verify crashed challenge=%s",
                factor_id, challenge["challenge_id"],
            )
            verified = False

        if not verified:
            still_alive = record_failed_attempt(challenge)
            if not still_alive:
                logger.info(
                    "verification challenge locked challenge=%s user=%s",
                    challenge["challenge_id"], request.user.pk,
                )
                return StapelErrorResponse(423, ERR_423_VERIFICATION_LOCKED)
            return StapelErrorResponse(400, ERR_400_VERIFICATION_FAILED)

        token = complete_challenge(challenge)
        from stapel_auth.sessions.services import AuditService

        AuditService.log(
            "step_up_verified",
            user=request.user,
            request=request,
            scope=challenge["scope"],
            factor=factor_id,
        )
        dto = VerificationCompleteResponse(verified=True, verification_token=token)
        return StapelResponse(self.get_complete_response_serializer_class()(dto))


class VerificationPreferenceViewSet(SerializerSeamsMixin, viewsets.ViewSet):
    """Per-user step-up policy preferences (stapel_core.verification levels).

    A preference row turns a ``default_on`` scope off (``enabled=False``) or
    an ``opt_in`` scope on (``enabled=True``); ``strict`` scopes ignore
    preferences. INVARIANT: disabling protection is itself a protected
    action — the ``enabled=False`` branch is decorated with
    ``@requires_verification(scope="verification.settings",
    level="default_on")``, so an attacker with a stolen session cannot
    silently switch step-up off. Enabling never requires step-up.
    """

    permission_classes = [permissions.IsAuthenticated]

    # Overridable serializer seams (see SerializerSeamsMixin).
    preference_request_serializer_class = VerificationPreferenceSerializer
    preference_response_serializer_class = VerificationPreferenceRowSerializer
    preferences_response_serializer_class = VerificationPreferencesResponseSerializer

    @extend_schema(
        description=(
            "The current user's step-up verification preferences: one row per "
            "scope the user has touched (enabled=False turns a default_on "
            "scope off, enabled=True turns an opt_in scope on). Scopes "
            "without a row follow the endpoint's level default; strict "
            "scopes ignore preferences entirely."
        ),
        responses={200: VerificationPreferencesResponseSerializer},
    )
    def list_preferences(self, request):
        from stapel_auth.models import VerificationPreference
        from stapel_auth.verification.dto import (
            VerificationPreferenceRow,
            VerificationPreferencesResponse,
        )

        rows = [
            VerificationPreferenceRow(scope=scope, enabled=enabled)
            for scope, enabled in VerificationPreference.objects.filter(
                user=request.user
            ).order_by("scope").values_list("scope", "enabled")
        ]
        dto = VerificationPreferencesResponse(preferences=rows)
        return StapelResponse(self.get_preferences_response_serializer_class()(dto))

    @extend_schema(
        description=(
            "Upsert a step-up verification preference {scope, enabled}. "
            "Enabling (enabled=true) applies immediately. Disabling "
            "(enabled=false) is itself step-up protected: without a fresh "
            "grant for scope verification.settings the request is rejected "
            "with the 403 verification envelope — complete a factor and "
            "retry. Both writes invalidate the cached policy, so protected "
            "endpoints see the change within one request."
        ),
        request=VerificationPreferenceSerializer,
        responses={
            200: VerificationPreferenceRowSerializer,
            400: StapelErrorSerializer,
            403: StapelErrorSerializer,
        },
    )
    def set_preference(self, request):
        serializer = self.get_preference_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        scope = serializer.validated_data["scope"]
        enabled = serializer.validated_data["enabled"]
        if enabled:
            # Turning protection ON never needs proof of presence.
            return self._apply_preference(request, scope, True)
        return self._disable_preference(request, scope)

    @requires_verification(scope="verification.settings", level="default_on")
    def _disable_preference(self, request, scope):
        """The step-up-guarded branch: switching protection OFF."""
        return self._apply_preference(request, scope, False)

    def _apply_preference(self, request, scope, enabled):
        from stapel_auth.models import VerificationPreference
        from stapel_auth.verification.dto import VerificationPreferenceRow

        VerificationPreference.objects.update_or_create(
            user=request.user, scope=scope, defaults={"enabled": enabled},
        )
        # The core caches resolved policies for POLICY_CACHE_TTL — drop the
        # entry so the change is visible on the next protected request.
        invalidate_policy_cache(request.user.pk)

        from stapel_auth.sessions.services import AuditService

        AuditService.log(
            "verification_preference_changed",
            user=request.user,
            request=request,
            scope=scope,
            enabled=enabled,
        )
        dto = VerificationPreferenceRow(scope=scope, enabled=enabled)
        return StapelResponse(self.get_preference_response_serializer_class()(dto))


# The decorator wraps only the disable branch (enabling must never demand
# step-up), but the endpoint's OpenAPI/flow docs still have to advertise the
# contract — mirror it onto the public PUT handler.
setattr(
    VerificationPreferenceViewSet.set_preference,
    VERIFICATION_ATTR,
    getattr(VerificationPreferenceViewSet._disable_preference, VERIFICATION_ATTR),
)
