"""SSO service: SAML 2.0 SP and OIDC RP implementations."""
import base64
import hashlib
import logging
import secrets
import uuid
import zlib
from datetime import datetime, timezone
from urllib.parse import urlencode


logger = logging.getLogger(__name__)

_SAML_NS = {
    'saml':  'urn:oasis:names:tc:SAML:2.0:assertion',
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'ds':    'http://www.w3.org/2000/09/xmldsig#',
}


def _get_base_url() -> str:
    from .conf import auth_settings
    return auth_settings.BACKEND_URL or auth_settings.FRONTEND_URL or ''


# =============================================================================
# SAML 2.0 SP
# =============================================================================

class SAMLService:
    @staticmethod
    def sp_entity_id(org_slug: str) -> str:
        return f'{_get_base_url()}/auth/api/sso/{org_slug}/saml/metadata/'

    @staticmethod
    def acs_url(org_slug: str) -> str:
        return f'{_get_base_url()}/auth/api/sso/{org_slug}/saml/acs/'

    @classmethod
    def generate_metadata(cls, org_slug: str) -> str:
        entity_id = cls.sp_entity_id(org_slug)
        acs = cls.acs_url(org_slug)
        return f'''<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{acs}"
        index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>'''

    @classmethod
    def build_authn_request(cls, org_slug: str, config) -> tuple[str, str]:
        """Returns (redirect_url, request_id) — caller should store request_id in Redis."""
        request_id = f'_{uuid.uuid4().hex}'
        issue_instant = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        entity_id = cls.sp_entity_id(org_slug)
        acs = cls.acs_url(org_slug)
        name_id_format = config.saml_name_id_format or 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

        xml = (
            f'<samlp:AuthnRequest'
            f' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            f' ID="{request_id}"'
            f' Version="2.0"'
            f' IssueInstant="{issue_instant}"'
            f' AssertionConsumerServiceURL="{acs}"'
            f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f'<saml:Issuer>{entity_id}</saml:Issuer>'
            f'<samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true"/>'
            f'</samlp:AuthnRequest>'
        )
        # Deflate (raw) + base64 for HTTP-Redirect binding
        deflated = zlib.compress(xml.encode('utf-8'))[2:-4]
        encoded = base64.b64encode(deflated).decode('ascii')
        params = urlencode({'SAMLRequest': encoded, 'RelayState': org_slug})
        return f'{config.saml_sso_url}?{params}', request_id

    @classmethod
    def parse_response(cls, config, saml_response_b64: str, org_slug: str = None) -> dict:
        """Verify signature and parse assertion. Returns user attributes dict.

        When *org_slug* is given (always the case for the ACS view) the
        assertion is additionally validated against:
          - AudienceRestriction == our SP entityID for this org,
          - InResponseTo == a request id we issued (stored in cache at login,
            consumed here so it can be used exactly once),
          - assertion ID replay (IDs cached until NotOnOrAfter).
        """
        try:
            from lxml import etree
            from signxml import XMLVerifier
        except ImportError:
            raise RuntimeError('lxml and signxml are required for SAML support. Run: pip install lxml signxml')

        raw = base64.b64decode(saml_response_b64)
        # Hardened parsing: attacker-supplied XML is parsed BEFORE signature
        # verification — entity resolution/DTDs here mean XXE (local file
        # disclosure, SSRF). Reject DOCTYPE outright and disable entities.
        import re as _re
        if _re.search(rb'<!DOCTYPE', raw, _re.IGNORECASE):
            raise ValueError('DOCTYPE is not allowed in SAML responses')
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            dtd_validation=False,
            load_dtd=False,
        )
        root = etree.fromstring(raw, parser=parser)

        # Normalise certificate
        cert_raw = config.saml_x509_cert.strip()
        if not cert_raw.startswith('-----'):
            # Raw base64 cert — wrap in PEM header
            cert_raw = f'-----BEGIN CERTIFICATE-----\n{cert_raw}\n-----END CERTIFICATE-----'

        verifier = XMLVerifier()
        verified = verifier.verify(root, x509_cert=cert_raw, expect_references=1)
        signed_root = verified.signed_xml

        # Parse assertion (may be the Response root or a nested Assertion element)
        assertion = signed_root.find('.//saml:Assertion', _SAML_NS)
        if assertion is None:
            assertion = signed_root  # signature was on the Assertion itself

        cls._validate_conditions(assertion)
        if org_slug is not None:
            cls._validate_audience(assertion, org_slug)
            cls._validate_in_response_to(assertion, root, org_slug)
            cls._check_assertion_replay(assertion)
        return cls._extract_attributes(assertion, config)

    @classmethod
    def _validate_conditions(cls, assertion):
        conditions = assertion.find('saml:Conditions', _SAML_NS)
        if conditions is None:
            return
        now = datetime.now(timezone.utc)
        not_before_str = conditions.get('NotBefore')
        not_after_str = conditions.get('NotOnOrAfter')
        if not_before_str:
            nb = cls._parse_saml_instant(not_before_str)
            if now < nb:
                raise ValueError(f'SAML assertion not yet valid (NotBefore={not_before_str})')
        if not_after_str:
            na = cls._parse_saml_instant(not_after_str)
            if now > na:
                raise ValueError(f'SAML assertion has expired (NotOnOrAfter={not_after_str})')

    @staticmethod
    def _parse_saml_instant(value: str) -> datetime:
        """Parse a SAML dateTime (with or without fractional seconds)."""
        for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ'):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        raise ValueError(f'Invalid SAML timestamp: {value!r}')

    @classmethod
    def _validate_audience(cls, assertion, org_slug: str) -> None:
        """AudienceRestriction, when present, must name our SP entityID.

        An assertion issued for a different SP (a different audience) must
        never be accepted here — otherwise any SP the IdP serves could replay
        its assertions against us.
        """
        audiences = assertion.findall(
            'saml:Conditions/saml:AudienceRestriction/saml:Audience', _SAML_NS,
        )
        if not audiences:
            return  # AudienceRestriction is optional per SAML core spec
        expected = cls.sp_entity_id(org_slug)
        values = [(a.text or '').strip() for a in audiences]
        if expected not in values:
            raise ValueError(
                f'SAML assertion audience {values!r} does not include SP entityID {expected!r}'
            )

    @classmethod
    def _validate_in_response_to(cls, assertion, response_root, org_slug: str) -> None:
        """InResponseTo must match a request id WE issued for this org.

        The id is stored in cache by the login view (saml_req:{slug}:{id})
        and consumed here — a response can only answer one outstanding
        AuthnRequest, and only once. Responses without InResponseTo are
        treated as IdP-initiated and allowed (nothing to correlate).
        """
        from django.core.cache import cache

        in_response_to = None
        # Prefer the signed SubjectConfirmationData inside the assertion.
        scd = assertion.find(
            'saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData', _SAML_NS,
        )
        if scd is not None and scd.get('InResponseTo'):
            in_response_to = scd.get('InResponseTo')
        elif response_root is not None and response_root.get('InResponseTo'):
            in_response_to = response_root.get('InResponseTo')

        if not in_response_to:
            logger.info('SAML response without InResponseTo (IdP-initiated) for %s', org_slug)
            return

        key = f'saml_req:{org_slug}:{in_response_to}'
        if not cache.get(key):
            raise ValueError(
                f'SAML InResponseTo {in_response_to!r} does not match an outstanding AuthnRequest'
            )
        cache.delete(key)  # consume: single use

    @classmethod
    def _check_assertion_replay(cls, assertion) -> None:
        """Reject an assertion whose ID was already accepted (replay).

        IDs are cached until the assertion's NotOnOrAfter — after that the
        Conditions check rejects it anyway.
        """
        from django.core.cache import cache

        assertion_id = assertion.get('ID')
        if not assertion_id:
            raise ValueError('SAML assertion has no ID attribute')

        ttl = 300  # fallback when no NotOnOrAfter present
        conditions = assertion.find('saml:Conditions', _SAML_NS)
        not_after_str = conditions.get('NotOnOrAfter') if conditions is not None else None
        if not_after_str:
            na = cls._parse_saml_instant(not_after_str)
            ttl = max(int((na - datetime.now(timezone.utc)).total_seconds()), 1)

        # cache.add is atomic: False means the ID was already stored → replay.
        if not cache.add(f'saml_assertion_seen:{assertion_id}', '1', ttl):
            raise ValueError(f'SAML assertion {assertion_id!r} replayed')

    @staticmethod
    def _extract_attributes(assertion, config) -> dict:
        name_id_el = assertion.find('.//saml:NameID', _SAML_NS)
        subject_id = name_id_el.text.strip() if name_id_el is not None else ''

        attrs: dict[str, str] = {}
        for attr_el in assertion.findall('.//saml:Attribute', _SAML_NS):
            name = attr_el.get('Name', '')
            values = [v.text or '' for v in attr_el.findall('saml:AttributeValue', _SAML_NS)]
            if values:
                attrs[name] = values[0]

        email_key  = config.attr_email or 'email'
        fname_key  = config.attr_first_name or 'firstName'
        lname_key  = config.attr_last_name or 'lastName'

        email      = attrs.get(email_key) or subject_id
        first_name = attrs.get(fname_key, '')
        last_name  = attrs.get(lname_key, '')

        return {
            'subject_id': subject_id,
            'email': email.lower().strip(),
            'first_name': first_name,
            'last_name': last_name,
        }


# =============================================================================
# OIDC RP
# =============================================================================

class OIDCService:
    _discovery_cache: dict[str, dict] = {}

    @classmethod
    def _discover(cls, discovery_url: str) -> dict:
        if discovery_url in cls._discovery_cache:
            return cls._discovery_cache[discovery_url]
        import requests as _req
        resp = _req.get(discovery_url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        cls._discovery_cache[discovery_url] = data
        return data

    @classmethod
    def authorization_url(cls, org_slug: str, config) -> tuple[str, dict]:
        """Returns (authorize_url, state_data) — caller stores state_data in Redis."""
        meta = cls._discover(config.oidc_discovery_url)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)
        # PKCE
        verifier = secrets.token_urlsafe(43)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b'=').decode()

        callback = f'{_get_base_url()}/auth/api/sso/{org_slug}/oidc/callback/'
        params = {
            'response_type': 'code',
            'client_id': config.oidc_client_id,
            'redirect_uri': callback,
            'scope': config.oidc_scopes or 'openid email profile',
            'state': state,
            'nonce': nonce,
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        }
        url = f'{meta["authorization_endpoint"]}?{urlencode(params)}'
        state_data = {
            'state': state,
            'nonce': nonce,
            'verifier': verifier,
            'org_slug': org_slug,
        }
        return url, state_data

    @classmethod
    def exchange_code(cls, org_slug: str, config, code: str, state_data: dict) -> dict:
        """Exchange auth code for user info. Returns {'email', 'first_name', 'last_name', 'subject_id'}."""
        import requests as _req
        meta = cls._discover(config.oidc_discovery_url)
        callback = f'{_get_base_url()}/auth/api/sso/{org_slug}/oidc/callback/'

        token_resp = _req.post(meta['token_endpoint'], data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': callback,
            'client_id': config.oidc_client_id,
            'client_secret': config.oidc_client_secret,
            'code_verifier': state_data.get('verifier', ''),
        }, timeout=15)
        token_resp.raise_for_status()
        tokens = token_resp.json()

        # Prefer userinfo endpoint over parsing id_token for simplicity
        userinfo_url = meta.get('userinfo_endpoint')
        if userinfo_url:
            ui_resp = _req.get(userinfo_url, headers={'Authorization': f'Bearer {tokens["access_token"]}'}, timeout=10)
            ui_resp.raise_for_status()
            info = ui_resp.json()
        else:
            # Fall back to id_token claims (no signature verification needed here —
            # we already trust the token server since we just got this token directly from it)
            import jwt as _jwt
            info = _jwt.decode(tokens['id_token'], options={'verify_signature': False})

        email = (info.get('email') or '').lower().strip()
        name  = info.get('name', '')
        given = info.get('given_name') or (name.split()[0] if name else '')
        family = info.get('family_name') or (name.split()[-1] if ' ' in name else '')

        return {
            'subject_id': info.get('sub', email),
            'email': email,
            'first_name': given,
            'last_name': family,
        }


# =============================================================================
# Shared: JIT provisioning + session issue
# =============================================================================

class SSOUserService:
    @staticmethod
    def get_or_create_user(org, attrs: dict):
        """JIT provision: find existing user by email or create; link membership."""
        from django.contrib.auth import get_user_model
        from .models import OrgMembership
        U = get_user_model()
        email = attrs['email']
        if not email:
            raise ValueError('SSO assertion missing email')

        user, created = U.objects.get_or_create(
            email=email,
            defaults={
                'is_active': True,
                'first_name': attrs.get('first_name', ''),
                'last_name': attrs.get('last_name', ''),
            },
        )
        if not created:
            # Sync name if it came from IdP
            changed = False
            if attrs.get('first_name') and not user.first_name:
                user.first_name = attrs['first_name']
                changed = True
            if attrs.get('last_name') and not user.last_name:
                user.last_name = attrs['last_name']
                changed = True
            if changed:
                user.save(update_fields=['first_name', 'last_name'])

        # Upsert org membership
        OrgMembership.objects.update_or_create(
            user=user, org=org,
            defaults={'sso_subject_id': attrs.get('subject_id', '')},
        )
        return user, created

    @staticmethod
    def issue_session_and_redirect(user, org, request):
        """Issue JWT session, set cookies, redirect to frontend."""
        from django.http import HttpResponseRedirect
        from stapel_core.django.jwt.utils import set_jwt_cookies
        from .views import _issue_session_tokens, _add_login_hints
        from .services import LoginNotificationService

        access_token, refresh_token = _issue_session_tokens(user, request)

        from stapel_core.django.jwt.provider import jwt_provider as _jwt
        from datetime import datetime, timezone as _tz
        from .services import SessionService, AuditService as _AS
        _rt_pl = _jwt.handler.decode_token(refresh_token, verify=False) or {}
        _at_pl = _jwt.handler.decode_token(access_token, verify=False) or {}
        _jti   = _rt_pl.get('jti', '')
        _exp   = datetime.fromtimestamp(_rt_pl.get('exp', 0), tz=_tz.utc)
        session = SessionService.create(user, _jti, _exp, request=request, access_jti=_at_pl.get('jti', ''))
        _AS.log('sso_login', user=user, request=request, session=session)
        if session:
            LoginNotificationService.check_and_notify(user, session)

        from .conf import auth_settings
        frontend_url = auth_settings.FRONTEND_URL or ''
        redirect_url = f'{frontend_url}/'
        response = HttpResponseRedirect(redirect_url)
        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)
