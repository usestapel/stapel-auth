"""Leaf module (zero package-internal imports, by design) so every layer that
needs the OTP code width — the DB field (models.py), the request serializers
(otp/serializers.py, password/serializers.py), the code-generation service
(otp/services.py) and the capabilities contract (oauth/services.py) — can
import the SAME constant without a circular import: models.py is imported by
otp/services.py, so the constant cannot live there or in any module that
itself imports models.py.
"""

#: Digits per email/phone OTP code. Changing this is a coordinated,
#: migration-carrying change (PhoneVerification.code / EmailVerification.code
#: are CharField(max_length=OTP_CODE_LENGTH)) — it is deliberately a plain
#: constant, not a STAPEL_AUTH runtime setting, so a host can't flip it
#: without also widening the DB column.
OTP_CODE_LENGTH = 4
