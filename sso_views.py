"""SSO views: SAML 2.0 SP + OIDC RP flows, org management (admin)."""
import json
import logging

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse, HttpResponseRedirect
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import permissions, serializers, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from stapel_core.django.errors import (
    IronErrorResponse, error_500_internal,
)

from .errors import (
    ERR_400_SSO_NOT_CONFIGURED,
    ERR_404_SSO_ORG_NOT_FOUND,
    ERR_409_SSO_ORG_SLUG_TAKEN,
)
from .models import Organization, SSOConfig
from .sso_service import OIDCService, SAMLService, SSOUserService

logger = logging.getLogger(__name__)

_OIDC_STATE_TTL = 600  # 10 min


def _frontend_url():
    return getattr(settings, 'FRONTEND_URL', 'https://app.example.com')


def _get_org(slug: str):
    try:
        return Organization.objects.get(slug=slug)
    except Organization.DoesNotExist:
        return None


def _get_active_config(org):
    try:
        cfg = org.sso_config
        return cfg if cfg.is_active else None
    except SSOConfig.DoesNotExist:
        return None


# =============================================================================
# Domain lookup — public, used by frontend to detect SSO orgs
# =============================================================================

class SSODomainLookupView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='Check if an email domain has SSO configured',
        parameters=[OpenApiParameter('domain', str, required=True, description='Email domain, e.g. acmecorp.com')],
        responses={
            200: {'type': 'object', 'properties': {
                'sso_required': {'type': 'boolean'},
                'org_slug': {'type': 'string', 'nullable': True},
                'protocol': {'type': 'string', 'nullable': True},
            }},
        },
        tags=['SSO'],
    )
    def get(self, request: Request):
        domain = request.query_params.get('domain', '').strip().lower().lstrip('@')
        if not domain:
            return Response({'sso_required': False, 'org_slug': None, 'protocol': None})
        org = Organization.objects.filter(domain=domain).select_related('sso_config').first()
        if not org:
            return Response({'sso_required': False, 'org_slug': None, 'protocol': None})
        try:
            cfg = org.sso_config
            if not cfg.is_active:
                return Response({'sso_required': False, 'org_slug': None, 'protocol': None})
            return Response({
                'sso_required': org.sso_enforced,
                'org_slug': org.slug,
                'protocol': cfg.protocol,
            })
        except SSOConfig.DoesNotExist:
            return Response({'sso_required': False, 'org_slug': None, 'protocol': None})


# =============================================================================
# SAML views
# =============================================================================

class SAMLMetadataView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='SAML SP metadata XML — register this with your IdP',
        tags=['SSO'],
        responses={200: None},
    )
    def get(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return IronErrorResponse(404, ERR_404_SSO_ORG_NOT_FOUND)
        xml = SAMLService.generate_metadata(slug)
        return HttpResponse(xml, content_type='application/xml; charset=utf-8')


class SSOLoginView(APIView):
    """Unified login entry point — dispatches to SAML or OIDC based on org config."""
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='Initiate SSO login (SAML or OIDC) — redirects to IdP',
        tags=['SSO'],
        responses={302: None},
    )
    def get(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return IronErrorResponse(404, ERR_404_SSO_ORG_NOT_FOUND)
        cfg = _get_active_config(org)
        if not cfg:
            return IronErrorResponse(400, ERR_400_SSO_NOT_CONFIGURED)

        if cfg.protocol == SSOConfig.PROTOCOL_SAML:
            try:
                redirect_url, request_id = SAMLService.build_authn_request(slug, cfg)
            except Exception as e:
                logger.error(f'SAML authn request error [{slug}]: {e}')
                return error_500_internal()
            cache.set(f'saml_req:{slug}:{request_id}', '1', 600)
            return HttpResponseRedirect(redirect_url)

        if cfg.protocol == SSOConfig.PROTOCOL_OIDC:
            try:
                url, state_data = OIDCService.authorization_url(slug, cfg)
            except Exception as e:
                logger.error(f'OIDC authorize error [{slug}]: {e}')
                return error_500_internal()
            cache.set(f'oidc_state:{state_data["state"]}', json.dumps(state_data), _OIDC_STATE_TTL)
            return HttpResponseRedirect(url)

        return IronErrorResponse(400, ERR_400_SSO_NOT_CONFIGURED)


class SAMLACSView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='SAML Assertion Consumer Service — IdP posts SAMLResponse here',
        tags=['SSO'],
        responses={302: None},
    )
    def post(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_org_not_found')
        cfg = _get_active_config(org)
        if not cfg or cfg.protocol != SSOConfig.PROTOCOL_SAML:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_not_configured')

        saml_response = request.data.get('SAMLResponse') or request.POST.get('SAMLResponse', '')
        if not saml_response:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        try:
            attrs = SAMLService.parse_response(cfg, saml_response)
        except Exception as e:
            logger.warning(f'SAML ACS parse error [{slug}]: {e}')
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        try:
            user, _ = SSOUserService.get_or_create_user(org, attrs)
        except ValueError as e:
            logger.warning(f'SAML JIT provisioning failed [{slug}]: {e}')
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        if not user.is_active:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=account_disabled')

        return SSOUserService.issue_session_and_redirect(user, org, request)


# =============================================================================
# OIDC views
# =============================================================================


class OIDCCallbackView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary='OIDC callback — IdP redirects here with auth code',
        tags=['SSO'],
        responses={302: None},
    )
    def get(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_org_not_found')
        cfg = _get_active_config(org)
        if not cfg or cfg.protocol != SSOConfig.PROTOCOL_OIDC:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_not_configured')

        error = request.query_params.get('error')
        if error:
            logger.warning(f'OIDC callback error [{slug}]: {error}')
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        code  = request.query_params.get('code', '')
        state = request.query_params.get('state', '')
        if not code or not state:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        state_raw = cache.get(f'oidc_state:{state}')
        if not state_raw:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')
        cache.delete(f'oidc_state:{state}')
        state_data = json.loads(state_raw)

        try:
            attrs = OIDCService.exchange_code(slug, cfg, code, state_data)
        except Exception as e:
            logger.warning(f'OIDC exchange error [{slug}]: {e}')
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        try:
            user, _ = SSOUserService.get_or_create_user(org, attrs)
        except ValueError as e:
            logger.warning(f'OIDC JIT provisioning failed [{slug}]: {e}')
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=sso_invalid_response')

        if not user.is_active:
            return HttpResponseRedirect(f'{_frontend_url()}/login?error=account_disabled')

        return SSOUserService.issue_session_and_redirect(user, org, request)


# =============================================================================
# Admin: Org + SSOConfig CRUD (staff only)
# =============================================================================

class _OrgSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'domain', 'sso_enforced', 'created_at']
        read_only_fields = ['id', 'created_at']


class _SSOConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSOConfig
        exclude = ['id', 'org', 'updated_at']


class SSOAdminViewSet(ViewSet):
    permission_classes = [permissions.IsAdminUser]

    @extend_schema(
        summary='List all SSO organizations',
        tags=['SSO Admin'],
        responses={200: _OrgSerializer(many=True)},
    )
    def list_orgs(self, request: Request):
        qs = Organization.objects.all().order_by('slug')
        return Response(_OrgSerializer(qs, many=True).data)

    @extend_schema(
        summary='Create a new SSO organization',
        tags=['SSO Admin'],
        request=_OrgSerializer,
        responses={201: _OrgSerializer},
    )
    def create_org(self, request: Request):
        slug = (request.data or {}).get('slug', '')
        if slug and Organization.objects.filter(slug=slug).exists():
            return IronErrorResponse(409, ERR_409_SSO_ORG_SLUG_TAKEN)
        ser = _OrgSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        org = ser.save()
        return Response(_OrgSerializer(org).data, status=status.HTTP_201_CREATED)

    @extend_schema(
        summary='Get an SSO organization with its config',
        tags=['SSO Admin'],
        responses={200: _OrgSerializer},
    )
    def get_org(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return IronErrorResponse(404, ERR_404_SSO_ORG_NOT_FOUND)
        data = _OrgSerializer(org).data
        try:
            data['config'] = _SSOConfigSerializer(org.sso_config).data
        except SSOConfig.DoesNotExist:
            data['config'] = None
        return Response(data)

    @extend_schema(
        summary='Update an SSO organization',
        tags=['SSO Admin'],
        request=_OrgSerializer,
        responses={200: _OrgSerializer},
    )
    def update_org(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return IronErrorResponse(404, ERR_404_SSO_ORG_NOT_FOUND)
        ser = _OrgSerializer(org, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    @extend_schema(
        summary='Delete an SSO organization',
        tags=['SSO Admin'],
        responses={204: None},
    )
    def delete_org(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return IronErrorResponse(404, ERR_404_SSO_ORG_NOT_FOUND)
        org.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        summary='Create or update SSO config for an organization',
        tags=['SSO Admin'],
        request=_SSOConfigSerializer,
        responses={200: _SSOConfigSerializer},
    )
    def upsert_config(self, request: Request, slug: str):
        org = _get_org(slug)
        if not org:
            return IronErrorResponse(404, ERR_404_SSO_ORG_NOT_FOUND)
        try:
            existing = org.sso_config
            ser = _SSOConfigSerializer(existing, data=request.data, partial=True)
        except SSOConfig.DoesNotExist:
            ser = _SSOConfigSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        cfg = ser.save(org=org)
        return Response(_SSOConfigSerializer(cfg).data)
