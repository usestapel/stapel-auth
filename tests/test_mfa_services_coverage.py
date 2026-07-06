"""Coverage tests for stapel_auth.mfa.services (TOTPService + PasskeyService).

TOTPService is exercised with real pyotp (valid codes computed live).
PasskeyService mocks only the external crypto boundary — webauthn's
verify_registration_response / verify_authentication_response — while the
real service logic (cache challenge handling, credential building, model
persistence) runs for real. registration_begin / authentication_begin run
against the real webauthn option generator.
"""
import hashlib
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from webauthn.helpers import bytes_to_base64url

from stapel_auth.mfa.services import PasskeyService, TOTPService
from stapel_auth.models import PasskeyCredential, TOTPDevice

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f'{uuid.uuid4().hex[:8]}@example.com',
        username=uuid.uuid4().hex[:12],
        password='testpass123',
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.replace('-', '').encode()).hexdigest()


# =============================================================================
# TOTPService — setup / confirm
# =============================================================================

class TOTPSetupConfirmTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()

    def test_setup_returns_secret_and_uri_and_pending_device(self):
        result = TOTPService.setup(self.user)
        self.assertIn('secret', result)
        self.assertIn('qr_uri', result)
        self.assertTrue(result['qr_uri'].startswith('otpauth://'))
        device = TOTPDevice.objects.get(user=self.user)
        self.assertFalse(device.is_active)
        self.assertEqual(device.secret, result['secret'])

    def test_setup_replaces_existing_pending_device(self):
        first = TOTPService.setup(self.user)
        second = TOTPService.setup(self.user)
        self.assertNotEqual(first['secret'], second['secret'])
        self.assertEqual(TOTPDevice.objects.filter(user=self.user).count(), 1)

    def test_confirm_success_activates_and_returns_backup_codes(self):
        setup = TOTPService.setup(self.user)
        code = pyotp.TOTP(setup['secret']).now()
        codes = TOTPService.confirm(self.user, code)
        self.assertEqual(len(codes), TOTPService.BACKUP_CODE_COUNT)
        device = TOTPDevice.objects.get(user=self.user)
        self.assertTrue(device.is_active)
        self.assertIsNotNone(device.confirmed_at)
        # Stored codes are hashed, not the plaintext returned.
        self.assertEqual(len(device.backup_codes), TOTPService.BACKUP_CODE_COUNT)
        self.assertNotIn(codes[0], device.backup_codes)
        self.assertIn(_hash_code(codes[0]), device.backup_codes)

    def test_confirm_no_pending_device_raises(self):
        with self.assertRaises(ValueError) as ctx:
            TOTPService.confirm(self.user, '000000')
        self.assertEqual(str(ctx.exception), 'no_pending_device')

    def test_confirm_invalid_code_raises(self):
        TOTPService.setup(self.user)
        with self.assertRaises(ValueError) as ctx:
            TOTPService.confirm(self.user, '000000')
        self.assertEqual(str(ctx.exception), 'invalid_code')


# =============================================================================
# TOTPService — disable / force_disable
# =============================================================================

class TOTPDisableTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.secret = pyotp.random_base32()
        self.backup_plain = 'ABCD-1234'
        self.device = TOTPDevice.objects.create(
            user=self.user,
            secret=self.secret,
            is_active=True,
            backup_codes=[_hash_code(self.backup_plain)],
        )

    def test_disable_with_valid_code(self):
        code = pyotp.TOTP(self.secret).now()
        self.assertTrue(TOTPService.disable(self.user, code=code))
        self.assertFalse(TOTPDevice.objects.filter(user=self.user).exists())

    def test_disable_with_backup_code(self):
        self.assertTrue(TOTPService.disable(self.user, backup_code=self.backup_plain))
        self.assertFalse(TOTPDevice.objects.filter(user=self.user).exists())

    def test_disable_wrong_code_returns_false(self):
        self.assertFalse(TOTPService.disable(self.user, code='000000'))
        self.assertTrue(TOTPDevice.objects.filter(user=self.user).exists())

    def test_disable_wrong_backup_code_returns_false(self):
        self.assertFalse(TOTPService.disable(self.user, backup_code='0000-0000'))
        self.assertTrue(TOTPDevice.objects.filter(user=self.user).exists())

    def test_disable_no_proof_returns_false(self):
        # Neither code nor backup_code — _verify_any falls through to False.
        self.assertFalse(TOTPService.disable(self.user))
        self.assertTrue(TOTPDevice.objects.filter(user=self.user).exists())

    def test_disable_no_active_device_returns_false(self):
        other = _make_user()
        self.assertFalse(TOTPService.disable(other, code='000000'))

    def test_force_disable_removes_active_device(self):
        self.assertTrue(TOTPService.force_disable(self.user))
        self.assertFalse(TOTPDevice.objects.filter(user=self.user).exists())

    def test_force_disable_no_device_returns_false(self):
        other = _make_user()
        self.assertFalse(TOTPService.force_disable(other))


# =============================================================================
# TOTPService — verify helpers, is_enabled, backup counts
# =============================================================================

class TOTPVerifyHelpersTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.secret = pyotp.random_base32()
        self.backup_plain = 'DEAD-BEEF'
        self.device = TOTPDevice.objects.create(
            user=self.user,
            secret=self.secret,
            is_active=True,
            backup_codes=[_hash_code(self.backup_plain)],
        )

    def test_verify_code_valid(self):
        code = pyotp.TOTP(self.secret).now()
        self.assertTrue(TOTPService.verify_code(self.user, code))

    def test_verify_code_invalid(self):
        self.assertFalse(TOTPService.verify_code(self.user, '000000'))

    def test_verify_code_no_device(self):
        self.assertFalse(TOTPService.verify_code(_make_user(), '000000'))

    def test_verify_backup_code_consumes(self):
        self.assertTrue(TOTPService.verify_backup_code(self.user, self.backup_plain))
        self.device.refresh_from_db()
        self.assertEqual(self.device.backup_codes, [])
        # Second use fails — code consumed.
        self.assertFalse(TOTPService.verify_backup_code(self.user, self.backup_plain))

    def test_verify_backup_code_unknown(self):
        self.assertFalse(TOTPService.verify_backup_code(self.user, 'NOPE-NOPE'))

    def test_verify_backup_code_no_device(self):
        self.assertFalse(TOTPService.verify_backup_code(_make_user(), 'AAAA-BBBB'))

    def test_is_enabled_true_and_false(self):
        self.assertTrue(TOTPService.is_enabled(self.user))
        self.assertFalse(TOTPService.is_enabled(_make_user()))

    def test_backup_codes_remaining_count(self):
        self.assertEqual(TOTPService.backup_codes_remaining(self.user), 1)

    def test_backup_codes_remaining_none_when_no_device(self):
        self.assertIsNone(TOTPService.backup_codes_remaining(_make_user()))


# =============================================================================
# TOTPService — challenge flow
# =============================================================================

class TOTPChallengeTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.secret = pyotp.random_base32()
        self.backup_plain = 'CAFE-F00D'
        self.device = TOTPDevice.objects.create(
            user=self.user,
            secret=self.secret,
            is_active=True,
            backup_codes=[_hash_code(self.backup_plain)],
        )

    def test_resolve_challenge_success_with_code(self):
        token = TOTPService.create_challenge(str(self.user.id))
        code = pyotp.TOTP(self.secret).now()
        resolved = TOTPService.resolve_challenge(token, code=code)
        self.assertEqual(resolved, self.user)
        # Challenge is consumed on success.
        self.assertIsNone(cache.get(f'totp_challenge:{token}'))

    def test_resolve_challenge_success_with_backup_code(self):
        token = TOTPService.create_challenge(str(self.user.id))
        resolved = TOTPService.resolve_challenge(token, backup_code=self.backup_plain)
        self.assertEqual(resolved, self.user)

    def test_resolve_challenge_unknown_token(self):
        self.assertIsNone(TOTPService.resolve_challenge('does-not-exist', code='000000'))

    def test_resolve_challenge_missing_user(self):
        token = TOTPService.create_challenge(str(uuid.uuid4()))
        self.assertIsNone(TOTPService.resolve_challenge(token, code='000000'))

    def test_resolve_challenge_no_active_device(self):
        user = _make_user()
        token = TOTPService.create_challenge(str(user.id))
        self.assertIsNone(TOTPService.resolve_challenge(token, code='000000'))

    def test_resolve_challenge_wrong_code_increments_failures(self):
        token = TOTPService.create_challenge(str(self.user.id))
        self.assertIsNone(TOTPService.resolve_challenge(token, code='000000'))
        self.assertEqual(cache.get(f'totp_challenge_fails:{token}'), 1)
        # Challenge still valid after a single failure.
        self.assertIsNotNone(cache.get(f'totp_challenge:{token}'))

    def test_resolve_challenge_burns_after_max_failures(self):
        token = TOTPService.create_challenge(str(self.user.id))
        for _ in range(TOTPService.MAX_CHALLENGE_FAILURES):
            self.assertIsNone(TOTPService.resolve_challenge(token, code='000000'))
        # Challenge and fail counter burned.
        self.assertIsNone(cache.get(f'totp_challenge:{token}'))
        self.assertIsNone(cache.get(f'totp_challenge_fails:{token}'))


# =============================================================================
# TOTPService — deprecated step-up wrappers
# =============================================================================

class TOTPStepUpTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.secret = pyotp.random_base32()
        TOTPDevice.objects.create(
            user=self.user, secret=self.secret, is_active=True, backup_codes=[],
        )

    def test_create_step_up_valid_emits_deprecation_and_returns_token(self):
        code = pyotp.TOTP(self.secret).now()
        with self.assertWarns(DeprecationWarning):
            token = TOTPService.create_step_up(self.user, code)
        self.assertIsNotNone(token)
        self.assertIsNotNone(cache.get(f'step_up:{self.user.id}:{token}'))

    def test_create_step_up_invalid_returns_none(self):
        with self.assertWarns(DeprecationWarning):
            token = TOTPService.create_step_up(self.user, '000000')
        self.assertIsNone(token)

    def test_consume_step_up_valid_then_invalid(self):
        token = TOTPService._issue_step_up_token(self.user, pyotp.TOTP(self.secret).now())
        self.assertIsNotNone(token)
        with self.assertWarns(DeprecationWarning):
            self.assertTrue(TOTPService.consume_step_up(self.user, token))
        # Second consume fails — token is one-time.
        with self.assertWarns(DeprecationWarning):
            self.assertFalse(TOTPService.consume_step_up(self.user, token))

    def test_consume_step_up_unknown_token(self):
        with self.assertWarns(DeprecationWarning):
            self.assertFalse(TOTPService.consume_step_up(self.user, 'nope'))


# =============================================================================
# PasskeyService helpers
# =============================================================================

def _reg_credential_data(cred_id_bytes=b'rawcredbytes', transports=None,
                         attachment=None, with_raw_id=True):
    data = {
        'id': 'credential-id-b64',
        'response': {
            'clientDataJSON': bytes_to_base64url(b'{"type":"webauthn.create"}'),
            'attestationObject': bytes_to_base64url(b'\xa0'),
        },
    }
    if with_raw_id:
        data['rawId'] = bytes_to_base64url(cred_id_bytes)
    if transports is not None:
        data['response']['transports'] = transports
    if attachment is not None:
        data['authenticatorAttachment'] = attachment
    return data


def _auth_credential_data(cred_id_bytes, with_user_handle=False, attachment=None):
    data = {
        'id': 'credential-id-b64',
        'rawId': bytes_to_base64url(cred_id_bytes),
        'response': {
            'clientDataJSON': bytes_to_base64url(b'{"type":"webauthn.get"}'),
            'authenticatorData': bytes_to_base64url(b'authdata'),
            'signature': bytes_to_base64url(b'sig'),
        },
    }
    if with_user_handle:
        data['response']['userHandle'] = bytes_to_base64url(b'userhandle')
    if attachment is not None:
        data['authenticatorAttachment'] = attachment
    return data


# =============================================================================
# PasskeyService — registration
# =============================================================================

class PasskeyRegistrationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()

    def test_registration_begin_stores_challenge(self):
        options_json = PasskeyService.registration_begin(self.user)
        self.assertIsInstance(options_json, str)
        self.assertIn('challenge', options_json)
        self.assertIsNotNone(cache.get(f'passkey_reg:{self.user.id}'))

    def test_registration_begin_excludes_existing_credentials(self):
        PasskeyCredential.objects.create(
            user=self.user,
            credential_id=b'existing-cred-id',
            public_key=b'pubkey',
            sign_count=0,
        )
        options_json = PasskeyService.registration_begin(self.user)
        self.assertIsInstance(options_json, str)

    def test_registration_complete_success(self):
        cache.set(f'passkey_reg:{self.user.id}', b'challenge-bytes', 300)
        cred_id = b'new-credential-id'
        fake_verification = SimpleNamespace(
            credential_id=cred_id,
            credential_public_key=b'the-public-key',
            sign_count=7,
            aaguid='00000000-0000-0000-0000-000000000000',
        )
        data = _reg_credential_data(transports=['usb', 'internal'], attachment='platform')
        with patch('webauthn.verify_registration_response', return_value=fake_verification):
            pc = PasskeyService.registration_complete(self.user, data, device_name='My Key')
        self.assertEqual(bytes(pc.credential_id), cred_id)
        self.assertEqual(bytes(pc.public_key), b'the-public-key')
        self.assertEqual(pc.sign_count, 7)
        self.assertEqual(pc.device_name, 'My Key')
        # Challenge is consumed.
        self.assertIsNone(cache.get(f'passkey_reg:{self.user.id}'))

    def test_registration_complete_no_transports_no_attachment_default_name(self):
        cache.set(f'passkey_reg:{self.user.id}', b'challenge-bytes', 300)
        fake_verification = SimpleNamespace(
            credential_id=b'cred-2',
            credential_public_key=b'pk-2',
            sign_count=0,
            aaguid=None,
        )
        data = _reg_credential_data()
        with patch('webauthn.verify_registration_response', return_value=fake_verification):
            pc = PasskeyService.registration_complete(self.user, data)
        self.assertEqual(pc.device_name, 'Passkey')
        self.assertEqual(pc.aaguid, '')
        self.assertEqual(pc.transports, [])

    def test_registration_complete_challenge_expired(self):
        data = _reg_credential_data()
        with self.assertRaises(ValueError) as ctx:
            PasskeyService.registration_complete(self.user, data)
        self.assertEqual(str(ctx.exception), 'challenge_expired')

    def test_registration_complete_verification_failure_propagates(self):
        cache.set(f'passkey_reg:{self.user.id}', b'challenge-bytes', 300)
        data = _reg_credential_data()
        with patch('webauthn.verify_registration_response',
                   side_effect=Exception('InvalidRegistrationResponse')):
            with self.assertRaises(Exception) as ctx:
                PasskeyService.registration_complete(self.user, data)
        self.assertIn('InvalidRegistrationResponse', str(ctx.exception))
        # No credential persisted on failure.
        self.assertFalse(PasskeyCredential.objects.filter(user=self.user).exists())


# =============================================================================
# PasskeyService — authentication
# =============================================================================

class PasskeyAuthenticationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        self.cred_id = uuid.uuid4().bytes
        self.pc = PasskeyCredential.objects.create(
            user=self.user,
            credential_id=self.cred_id,
            public_key=b'stored-public-key',
            sign_count=3,
            is_active=True,
        )

    def test_authentication_begin_with_user(self):
        session_key, options_json = PasskeyService.authentication_begin(self.user)
        self.assertIsInstance(session_key, str)
        self.assertIn('challenge', options_json)
        stored = cache.get(f'passkey_auth:{session_key}')
        self.assertEqual(stored['user_id'], str(self.user.id))

    def test_authentication_begin_usernameless(self):
        session_key, options_json = PasskeyService.authentication_begin(None)
        stored = cache.get(f'passkey_auth:{session_key}')
        self.assertIsNone(stored['user_id'])

    def test_authentication_complete_success(self):
        session_key = 'sess-1'
        cache.set(f'passkey_auth:{session_key}',
                  {'challenge': b'challenge-bytes', 'user_id': str(self.user.id)}, 300)
        fake_verification = SimpleNamespace(new_sign_count=9)
        data = _auth_credential_data(self.cred_id, with_user_handle=True, attachment='platform')
        with patch('webauthn.verify_authentication_response', return_value=fake_verification):
            user, pc = PasskeyService.authentication_complete(session_key, data)
        self.assertEqual(user, self.user)
        pc.refresh_from_db()
        self.assertEqual(pc.sign_count, 9)
        self.assertIsNotNone(pc.last_used_at)
        self.assertIsNone(cache.get(f'passkey_auth:{session_key}'))

    def test_authentication_complete_challenge_expired(self):
        data = _auth_credential_data(self.cred_id)
        with self.assertRaises(ValueError) as ctx:
            PasskeyService.authentication_complete('missing', data)
        self.assertEqual(str(ctx.exception), 'challenge_expired')

    def test_authentication_complete_unknown_credential(self):
        session_key = 'sess-2'
        cache.set(f'passkey_auth:{session_key}',
                  {'challenge': b'challenge-bytes', 'user_id': None}, 300)
        data = _auth_credential_data(b'unregistered-cred-id')
        with self.assertRaises(ValueError) as ctx:
            PasskeyService.authentication_complete(session_key, data)
        self.assertEqual(str(ctx.exception), 'unknown_credential')

    def test_authentication_complete_verification_failure_propagates(self):
        session_key = 'sess-3'
        cache.set(f'passkey_auth:{session_key}',
                  {'challenge': b'challenge-bytes', 'user_id': str(self.user.id)}, 300)
        data = _auth_credential_data(self.cred_id)
        with patch('webauthn.verify_authentication_response',
                   side_effect=Exception('InvalidAuthenticationResponse')):
            with self.assertRaises(Exception) as ctx:
                PasskeyService.authentication_complete(session_key, data)
        self.assertIn('InvalidAuthenticationResponse', str(ctx.exception))
