"""Where a signup came from — the ad click that produced the account.

**Why the server has to hold this at all.** Browser-side conversion
reporting answers "which campaign paid for this account?" only while the
advertising platform can still tie the *session* the event fired in to the
*session* the ad click landed in. That tie breaks for reasons that have
nothing to do with the code: an OTP letter opened in a webmail tab starts a
new session with a referral source, an OAuth round trip through the
provider does the same, thirty minutes between the click and the sign-up
ends the session outright, and a visitor who never answered a consent
banner has no session id to tie anything to. In a product where signing up
*is* one of those four shapes, the session tie is not an edge case — it is
the normal path, and it fails silently, which is the worst way for a
measurement to fail.

Offline conversion import is the one channel that needs no cookie at the
moment of conversion: the client hands the click identifier to the server
once, at registration, and the server later reports the conversion against
that identifier directly. It is also the only channel that can report a
conversion the browser never witnessed — an account that starts paying
three weeks after it registered. That conversion, not the sign-up, is the
goal worth bidding on, and until the identifier is stored somewhere durable
there is no way to name it.

So one row per account, written at the moment the account is born.

**What is stored, and what is not.** The click identifier and which
platform's identifier it is (see :data:`CLICK_ID_TYPES` — every ad platform
names its own parameter and none of them are interchangeable, so the caller
says which one it is holding rather than letting the server guess), the
time the client captured it (the upload requires the click time), and the
five standard campaign tags. Nothing here is invented server-side: if the
client sends no ``attribution`` object, no row exists, and that is the
honest answer to "where did this account come from" rather than a guess.

**A campaign tag with no click identifier is still an answer.** Not every
channel puts a click id on the landing URL: an email campaign, a price
aggregator, a paid placement that only carries ``utm_*`` — each of them
brings a real visitor that a click-id-only record would report as
"direct". So ``click_id`` is optional as long as ``utm.source`` names the
channel; what is refused is a record that says nothing at all, or one that
carries an identifier without saying which platform issued it (an offline
upload cannot post that anywhere).

**Never overwrite with an older capture.** A client that replays a stale
cookie must not demote a fresher click. The last click wins, and "last" is
decided by ``captured_at``, not by arrival order — retries, queued requests
and a second tab all reorder arrival, and none of them reorder the clock.

**Storing it must never be able to refuse an account.** Attribution is a
marketing record; registration is the product. Every write here is wrapped
so that a missing table (a host that pinned the release and has not
migrated yet), a database hiccup, or a malformed row logs loudly and
returns ``None`` instead of turning a working sign-up into a 500. The same
holds for the input: a malformed ``attribution`` object on a registration
request is dropped with a WARNING and the account is created without it.
The opposite trade — losing accounts to keep a marketing row honest — is
not one any deployment would choose.

**A guest is an account, and its attribution follows it.** ``POST
/anonymous/`` records the object like every other door. Promotion keeps
the row (it is the same user); a merge into an existing account moves the
guest's row onto the survivor, under the same newer-capture rule
(:func:`carry_over_on_merge`).
"""
from __future__ import annotations

import logging
import re

from rest_framework import serializers
from rest_framework.fields import empty
from stapel_core.django.api.errors import StapelValidationError

from stapel_auth.errors import ERR_400_ATTRIBUTION_INVALID

logger = logging.getLogger(__name__)

#: The click-identifier flavours an offline conversion upload can name.
#: They are not interchangeable — each platform's upload names its own
#: field, and a ``gbraid`` sent as a ``gclid`` is rejected rather than
#: silently coerced — so the caller states which one it holds:
#:
#: * ``gclid``/``gbraid``/``wbraid`` — Google Ads; the last two arrive
#:   instead of a ``gclid`` when the visitor declined app tracking;
#: * ``yclid`` — Yandex Direct;
#: * ``fbclid`` — Meta;
#: * ``ttclid`` — TikTok Ads.
#:
#: The list is deliberately closed: a stored identifier nobody can name a
#: destination for is a column that never gets uploaded anywhere.
CLICK_ID_TYPES = ('gclid', 'gbraid', 'wbraid', 'yclid', 'fbclid', 'ttclid')

#: The five campaign tags that have a standard meaning. Anything else in the
#: ``utm`` object is ignored rather than refused — a client that adds its
#: own tag should not fail a registration over it.
UTM_KEYS = ('source', 'medium', 'campaign', 'term', 'content')

#: Longest click identifier accepted. Real ``gclid`` values run ~100
#: characters; the ceiling is generous and exists so an unbounded string
#: cannot be posted into the column.
CLICK_ID_MAX_LENGTH = 512

#: Longest campaign tag accepted.
UTM_MAX_LENGTH = 255

#: The landing surface that sent the visitor (``transcribe_hero``,
#: ``header_mobile_cta``): a short machine slug, not free text.
LANDING_REF_MAX_LENGTH = 64
LANDING_REF_PATTERN = r'^[a-z0-9_]+$'
_LANDING_REF_RE = re.compile(r'[a-z0-9_]{1,%d}' % LANDING_REF_MAX_LENGTH)


#: Help text shared by every request that may register an account. Kept in
#: one string because it is the same promise on every door: optional, never
#: invented server-side, stored only when this call actually CREATES the
#: account (a login carries no new attribution).
ATTRIBUTION_HELP = (
    "Optional advertising attribution captured by the client on the landing "
    "page: {click_id?, click_id_type?: gclid|gbraid|wbraid|yclid|fbclid|"
    "ttclid, captured_at, utm?, landing_ref?}. The click identifier may be "
    "omitted when utm.source or landing_ref names the channel (an email or "
    "aggregator landing carries no click id); an identifier without its "
    "type, and a record carrying none of the three, are malformed. Stored "
    "against the account only when this call registers it; ignored on a "
    "login. Unknown keys are ignored; a malformed object is dropped (logged "
    "server-side) and never refuses the request, and an invalid landing_ref "
    "is dropped on its own."
)


class SignupUtmSerializer(serializers.Serializer):
    """The five standard campaign tags. Every one optional, all blankable."""

    source = serializers.CharField(
        max_length=UTM_MAX_LENGTH, required=False, allow_blank=True
    )
    medium = serializers.CharField(
        max_length=UTM_MAX_LENGTH, required=False, allow_blank=True
    )
    campaign = serializers.CharField(
        max_length=UTM_MAX_LENGTH, required=False, allow_blank=True
    )
    term = serializers.CharField(
        max_length=UTM_MAX_LENGTH, required=False, allow_blank=True
    )
    content = serializers.CharField(
        max_length=UTM_MAX_LENGTH, required=False, allow_blank=True
    )


class SignupAttributionSerializer(serializers.Serializer):
    """The optional ``attribution`` object a registration request may carry.

    Unknown keys are ignored — DRF's default, and the right one here: the
    client-side capture library is versioned independently of this service,
    and a tag it learns to collect next month must not start refusing
    sign-ups. Anything *malformed* is judged with a single fleet error key
    (``error.400.attribution_invalid``) rather than a per-field report; as a
    request field the whole object is then dropped with a warning
    (:meth:`run_validation`), because a registration is never refused over
    a marketing record.

    Each part of the record is optional and the object is still not a
    free-for-all — :meth:`to_internal_value` refuses the three shapes that
    could not be reported anywhere: a ``click_id`` with no type (no upload
    field to post it to), a type naming no identifier, and a record that
    carries no identifier, no ``utm.source`` and no ``landing_ref``.
    """

    click_id = serializers.CharField(
        max_length=CLICK_ID_MAX_LENGTH,
        required=False,
        help_text=(
            "The advertising click identifier captured from the landing URL. "
            "Optional: a channel that puts no click id on the URL (email, an "
            "aggregator, an untagged referral) still attributes through "
            "utm.source. Sent with it, click_id_type is required."
        ),
    )
    click_id_type = serializers.ChoiceField(
        choices=[(value, value) for value in CLICK_ID_TYPES],
        required=False,
        help_text=(
            "Which platform's identifier click_id is. The offline conversion "
            "upload names the field explicitly and does not guess, so this "
            "cannot be inferred from the value: gclid/gbraid/wbraid are "
            "Google Ads (the last two arrive instead of a gclid when the "
            "visitor declined app tracking), yclid is Yandex Direct, fbclid "
            "Meta, ttclid TikTok Ads. Required whenever click_id is sent, "
            "and meaningless without it."
        ),
    )
    captured_at = serializers.DateTimeField(
        help_text=(
            "When the client captured the identifier (ISO 8601). Required: "
            "an offline conversion upload has to state the click time, and "
            "it is also how a stale replay is told from a fresher click."
        ),
    )
    utm = SignupUtmSerializer(
        required=False,
        allow_null=True,
        help_text="Standard campaign tags read off the same landing URL.",
    )
    landing_ref = serializers.RegexField(
        LANDING_REF_PATTERN,
        max_length=LANDING_REF_MAX_LENGTH,
        required=False,
        help_text=(
            "The landing surface the visitor clicked through (the landing "
            "link's `ref`), e.g. transcribe_hero. At most 64 characters of "
            "[a-z0-9_]; any other value is dropped on its own, never "
            "refusing the rest of the record."
        ),
    )

    def run_validation(self, data=empty):
        """As a request field, a malformed object is dropped, never a 400.

        Called as the root serializer (:func:`parse_signup_attribution`) it
        still raises, so a Python caller can tell a bad mapping apart.
        """
        try:
            return super().run_validation(data)
        except serializers.ValidationError:
            if self.parent is None:
                raise
            logger.warning(
                "stapel-auth: dropping a malformed signup attribution "
                "(the registration itself is unaffected)"
            )
            return None

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise StapelValidationError(ERR_400_ATTRIBUTION_INVALID)
        data = _with_valid_landing_ref(_without_blank_identifier(data))
        try:
            value = super().to_internal_value(data)
        except serializers.ValidationError:
            # Collapse the nested report into the one key a client can act
            # on. Raised from here (not from validate()) so the parent
            # serializer records it against the `attribution` field and the
            # fleet error handler recovers the registered key verbatim.
            raise StapelValidationError(ERR_400_ATTRIBUTION_INVALID) from None
        return _coherent(value)


def _without_blank_identifier(data):
    """``click_id``/``click_id_type`` sent blank mean "absent", not "invalid".

    Done before field validation rather than by declaring the fields
    ``allow_blank`` on purpose. A blank-tolerant ChoiceField renders in
    OpenAPI as the enum *or* a separate blank enum, which puts an empty
    string into every generated client's union for a value that is not a
    click identifier — the contract would say the wire has seven kinds of
    identifier, one of which is nothing. Normalising here keeps the emitted
    enum exactly the platforms we can upload to, while a capture library
    that writes ``click_id: ""`` for "the landing URL had none" still means
    what it says: the same thing as omitting the key. This also lets the
    flat-query and state readers, which build the mapping with blanks for
    the keys they did not find, hand it straight to the same validator.
    """
    trimmed = dict(data)
    for key in ('click_id', 'click_id_type'):
        value = trimmed.get(key)
        if isinstance(value, str) and not value.strip():
            del trimmed[key]
    return trimmed


def _with_valid_landing_ref(data):
    """Drop a ``landing_ref`` that is not a slug, keeping the rest.

    The ref is a secondary tag: a bad one must not cost the click id or the
    campaign that came with it.
    """
    if 'landing_ref' not in data:
        return data
    value = data.get('landing_ref')
    if isinstance(value, str) and _LANDING_REF_RE.fullmatch(value):
        return data
    trimmed = dict(data)
    del trimmed['landing_ref']
    if value not in (None, ''):
        logger.warning(
            "stapel-auth: dropping an invalid landing_ref on a signup "
            "attribution (at most %d characters of [a-z0-9_])",
            LANDING_REF_MAX_LENGTH,
        )
    return trimmed


def _coherent(value):
    """Refuse the attribution shapes nothing could ever be reported from.

    Field-level validation cannot see across fields, and each field on its
    own is now optional, so this is where the record is judged as a whole.
    Three shapes are refused, all for the same reason — there is no channel
    that could consume them:

    * a ``click_id`` with no ``click_id_type``: an offline upload names the
      field it posts to, so an identifier of unknown provenance has no
      destination and guessing one is how a gbraid gets rejected as a gclid;
    * a ``click_id_type`` naming no identifier: a platform label with
      nothing under it;
    * no identifier, no ``utm.source`` and no ``landing_ref``: an empty
      record, which would occupy the account's one attribution row while
      saying nothing — strictly worse than the honest "no row at all".

    Blank strings are normalised to absent first: a capture library that
    writes ``click_id: ""`` for "the URL had none" means the same thing as
    one that omits the key, and the two must not disagree.
    """
    click_id = (value.get('click_id') or '').strip()
    click_id_type = value.get('click_id_type') or ''
    utm_source = ((value.get('utm') or {}).get('source') or '').strip()
    landing_ref = value.get('landing_ref') or ''

    if bool(click_id) != bool(click_id_type):
        raise StapelValidationError(ERR_400_ATTRIBUTION_INVALID)
    if not click_id and not utm_source and not landing_ref:
        raise StapelValidationError(ERR_400_ATTRIBUTION_INVALID)

    value['click_id'] = click_id
    value['click_id_type'] = click_id_type
    value['landing_ref'] = landing_ref
    return value


def record_signup_attribution(user, attribution):
    """Store (or refresh) the ad attribution of an account that just registered.

    ``attribution`` is the validated mapping produced by
    :class:`SignupAttributionSerializer` —
    ``{"click_id", "click_id_type", "captured_at", "utm"?}``, where the
    identifier pair is blank on a UTM-only record — or ``None`` when the
    client sent nothing, which is the common case and not an error.

    Returns the stored row, or ``None`` when there was nothing to store,
    when the deployment has the axis switched off, or when the write failed
    (see the module docstring: this call cannot be allowed to fail a
    registration).

    An existing row is replaced only by a *newer* capture. Equal timestamps
    change nothing: a replay of the same click is not new information.
    """
    if not attribution:
        return None

    from stapel_auth.conf import auth_settings

    if not auth_settings.AUTH_SIGNUP_ATTRIBUTION:
        return None

    try:
        return _write(user, attribution)
    except Exception:  # pragma: no cover - defensive; see module docstring
        logger.exception(
            "stapel-auth: could not store signup attribution for user %s "
            "(the registration itself is unaffected)",
            getattr(user, 'pk', None),
        )
        return None


def _write(user, attribution):
    from django.db import transaction

    from stapel_auth.models import SignupAttribution

    captured_at = attribution['captured_at']
    utm = attribution.get('utm') or {}
    fields = {
        # Blank on a UTM-only record, never null: the column says "this
        # landing carried no click id", which is a fact, not a gap.
        'click_id': attribution.get('click_id') or '',
        'click_id_type': attribution.get('click_id_type') or '',
        'captured_at': captured_at,
        'landing_ref': attribution.get('landing_ref') or '',
    }
    for key in UTM_KEYS:
        fields[f'utm_{key}'] = utm.get(key) or ''

    with transaction.atomic():
        # select_for_update is a no-op on SQLite and the real thing on
        # PostgreSQL; the row is per-user, so the lock is held for the
        # width of one account, not the table.
        row = (
            SignupAttribution.objects.select_for_update()
            .filter(user=user)
            .first()
        )
        if row is None:
            return SignupAttribution.objects.create(user=user, **fields)
        if row.captured_at >= captured_at:
            # An older (or identical) capture is not news. Returning the
            # standing row rather than None keeps the caller from having to
            # tell "refused" from "failed".
            return row
        for name, value in fields.items():
            setattr(row, name, value)
        row.save(update_fields=[*fields, 'updated_at'])
        return row


def attribution_as_dict(row):
    """Serialize a stored row for the ``auth.signup_attribution`` Function."""
    if row is None:
        return None
    return {
        'user_id': str(row.user_id),
        'click_id': row.click_id,
        'click_id_type': row.click_id_type,
        'captured_at': row.captured_at.isoformat(),
        'utm': {key: getattr(row, f'utm_{key}') for key in UTM_KEYS},
        'landing_ref': row.landing_ref,
        'created_at': row.created_at.isoformat(),
        'updated_at': row.updated_at.isoformat(),
    }


def attribution_from_query(query_params):
    """Read an attribution object off a *redirect* flow's query string.

    The authorization-code OAuth flow has no request body to carry the
    object: the browser is sent to the provider and comes back on a URL
    nobody but the provider controls. So the click identifier is handed to
    ``/oauth/{provider}/authorize/`` as flat query parameters, parked in the
    same server-side state entry that already pins the flow, and read back
    at the callback — the client never has to re-present it, and it never
    rides the provider's redirect.

    Tolerant, because a navigation cannot be corrected by the person on it:

    * campaign tags are read as ``utm_<key>`` or as the bare ``<key>``
      (``source``, ``medium``, ...); ``utm_<key>`` wins when both are there;
    * a missing ``captured_at`` is now — the query IS the navigation;
    * ``ref`` is the landing surface, stored as ``landing_ref``.

    Returns the same mapping shape the body serializer produces, or ``None``
    when the query carries no click identifier, ``source`` or ``ref`` — and
    ``None`` for a malformed one too, dropped with a warning: the response
    to this request is a redirect to a provider's login screen, and a JSON
    error in somebody's address bar would take the sign-in down over a
    marketing tag.
    """
    from django.utils import timezone

    click_id = (query_params.get('click_id') or '').strip()
    utm = {}
    for key in UTM_KEYS:
        value = query_params.get(f'utm_{key}') or query_params.get(key)
        if value:
            utm[key] = value
    landing_ref = query_params.get('ref') or ''
    # A sign-in navigation that carries no advertising tag at all is the
    # ordinary case, and asking the serializer about it would only produce
    # a warning per login.
    if not click_id and not utm.get('source') and not landing_ref:
        return None
    payload = {
        'click_id': click_id,
        'click_id_type': query_params.get('click_id_type') or '',
        'captured_at': (
            query_params.get('captured_at') or timezone.now().isoformat()
        ),
    }
    if utm:
        payload['utm'] = utm
    if landing_ref:
        payload['landing_ref'] = landing_ref
    return _parse_or_drop(payload, 'an OAuth authorize query')


def _parse_or_drop(payload, where):
    """:func:`parse_signup_attribution`, or ``None`` with a warning."""
    if not payload:
        return None
    try:
        return parse_signup_attribution(payload)
    except Exception:
        logger.warning(
            "stapel-auth: dropping a malformed attribution on %s "
            "(the sign-in itself is unaffected)",
            where,
        )
        return None


def lenient_signup_attribution(payload):
    """Validate a raw request-body mapping; ``None`` (logged) when malformed.

    For a door that reads its body field by field instead of through a
    serializer — the attribution can never refuse the registration.
    """
    return _parse_or_drop(payload, 'a registration request')


def parse_signup_attribution(payload):
    """Validate a raw attribution mapping. Raises the fleet 400 envelope.

    Used by the query-string reader and available to any caller holding a
    mapping that did not come through a request serializer. Unknown keys are
    ignored; anything malformed raises
    ``StapelValidationError(error.400.attribution_invalid)``.
    """
    serializer = SignupAttributionSerializer(data=payload)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


def attribution_of(user):
    """The stored row for ``user``, or ``None``."""
    from stapel_auth.models import SignupAttribution

    return SignupAttribution.objects.filter(user=user).first()


def to_state(attribution):
    """Flatten a validated attribution into JSON-safe primitives.

    The OAuth redirect flow parks it in the cache between ``/authorize/`` and
    ``/callback/``. A cache backend serializing to JSON (rather than pickle)
    cannot carry a ``datetime``, and the failure would show up only on the
    deployment that configured that backend — so the value is flattened here
    instead of relying on the backend's tolerance.
    """
    if not attribution:
        return None
    payload = {
        'click_id': attribution.get('click_id') or '',
        'click_id_type': attribution.get('click_id_type') or '',
        'captured_at': attribution['captured_at'].isoformat(),
    }
    utm = attribution.get('utm') or {}
    if utm:
        payload['utm'] = {key: value for key, value in utm.items() if value}
    if attribution.get('landing_ref'):
        payload['landing_ref'] = attribution['landing_ref']
    return payload


def from_state(payload):
    """Re-validate what :func:`to_state` parked. ``None`` for anything unusable.

    Unusable here means an expired or hand-edited state entry, not a client
    error: the request that could have been refused is long finished, so a
    broken entry is dropped with a warning rather than raised at somebody
    who is merely finishing a sign-in.
    """
    return _parse_or_drop(payload, 'an OAuth state entry')


def carry_over_on_merge(guest_id, survivor):
    """Move a merged guest's attribution onto the account that absorbs it.

    Called inside :func:`stapel_auth.otp.services.merge_anonymous_into`
    before the guest row (and, by cascade, its attribution) is deleted. The
    guest door recorded where the visitor came from; signing in to an
    existing account must not erase that. The newer-capture rule decides
    against a row the survivor already holds.

    Runs in its own savepoint and never raises: a failure here logs and the
    merge goes on.
    """
    from django.db import transaction

    from stapel_auth.conf import auth_settings
    from stapel_auth.models import SignupAttribution

    if not auth_settings.AUTH_SIGNUP_ATTRIBUTION:
        return None
    try:
        with transaction.atomic():
            rows = SignupAttribution.objects.select_for_update()
            guest_row = rows.filter(user_id=guest_id).first()
            if guest_row is None:
                return None
            kept = rows.filter(user=survivor).first()
            if kept is None:
                guest_row.user = survivor
                guest_row.save(update_fields=['user', 'updated_at'])
                return guest_row
            if kept.captured_at >= guest_row.captured_at:
                return kept
            fields = [
                'click_id', 'click_id_type', 'captured_at', 'landing_ref',
                *(f'utm_{key}' for key in UTM_KEYS),
            ]
            for name in fields:
                setattr(kept, name, getattr(guest_row, name))
            kept.save(update_fields=[*fields, 'updated_at'])
            return kept
    except Exception:
        logger.exception(
            "stapel-auth: could not carry signup attribution from guest %s "
            "to user %s (the merge itself is unaffected)",
            guest_id,
            getattr(survivor, 'pk', None),
        )
        return None
