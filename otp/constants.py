"""Leaf module (zero package-internal imports, by design) so every layer that
needs the OTP code width — the DB field (models.py), the request serializers
(otp/serializers.py, password/serializers.py), the code-generation service
(otp/services.py) and the capabilities contract (oauth/services.py) — can
import the SAME constant without a circular import: models.py is imported by
otp/services.py, so the constant cannot live there or in any module that
itself imports models.py.
"""

#: STORAGE/WIRE CAP for email/phone OTP codes (DB columns + serializer
#: max_length). Deliberately a plain constant (not a runtime setting): the DB
#: column width can't follow settings. 8 accommodates 4-8 digit deployments.
#: The GENERATED length is the runtime setting STAPEL_AUTH["OTP_LENGTH"]
#: (default 4, must be <= this cap — enforced by a system check in checks.py).
OTP_CODE_LENGTH = 8
