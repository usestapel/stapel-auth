# stapel: expand
# verified: pure column widening of SSOConfig.saml_sso_url, saml_slo_url and
# oidc_discovery_url (all Django URLField) from the implicit default
# varchar(200) to varchar(500) — same class of fix as core users_user.avatar
# (0007). Forward- and backward-compatible (a grow never truncates existing
# data and old code writing <=200 still fits), so no N-1 window is needed.
# Prevents StringDataRightTruncation for real-world IdP SSO/SLO/discovery
# URLs (Okta/Azure AD routinely exceed 200 chars with encoded query params).
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0013_staff_role_assignment"),
    ]

    operations = [
        migrations.AlterField(
            model_name="ssoconfig",
            name="saml_sso_url",
            field=models.URLField(blank=True, max_length=500, help_text="IdP SSO URL (redirect binding)"),
        ),
        migrations.AlterField(
            model_name="ssoconfig",
            name="saml_slo_url",
            field=models.URLField(blank=True, max_length=500, help_text="IdP SLO URL (optional)"),
        ),
        migrations.AlterField(
            model_name="ssoconfig",
            name="oidc_discovery_url",
            field=models.URLField(blank=True, max_length=500, help_text=".well-known/openid-configuration URL"),
        ),
    ]
