import uuid
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0009_add_access_jti_to_session'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('slug', models.SlugField(max_length=100, unique=True)),
                ('domain', models.CharField(blank=True, default='', help_text='Email domain tied to this org, e.g. acmecorp.com', max_length=253, unique=True)),
                ('sso_enforced', models.BooleanField(default=False, help_text='If true, members must log in via SSO only')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'db_table': 'sso_organizations'},
        ),
        migrations.CreateModel(
            name='SSOConfig',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('org', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='sso_config', to='stapel_auth.organization')),
                ('protocol', models.CharField(choices=[('saml', 'SAML 2.0'), ('oidc', 'OIDC')], max_length=10)),
                ('is_active', models.BooleanField(default=True)),
                ('saml_entity_id', models.CharField(blank=True, help_text='IdP entity ID / issuer', max_length=500)),
                ('saml_sso_url', models.URLField(blank=True, help_text='IdP SSO URL (redirect binding)')),
                ('saml_slo_url', models.URLField(blank=True, help_text='IdP SLO URL (optional)')),
                ('saml_x509_cert', models.TextField(blank=True, help_text='IdP signing certificate (PEM or raw base64)')),
                ('saml_name_id_format', models.CharField(blank=True, default='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', max_length=200)),
                ('attr_email', models.CharField(blank=True, default='email', max_length=200)),
                ('attr_first_name', models.CharField(blank=True, default='firstName', max_length=200)),
                ('attr_last_name', models.CharField(blank=True, default='lastName', max_length=200)),
                ('oidc_client_id', models.CharField(blank=True, max_length=200)),
                ('oidc_client_secret', models.CharField(blank=True, max_length=500)),
                ('oidc_discovery_url', models.URLField(blank=True, help_text='.well-known/openid-configuration URL')),
                ('oidc_scopes', models.CharField(blank=True, default='openid email profile', max_length=200)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'db_table': 'sso_configs'},
        ),
        migrations.CreateModel(
            name='OrgMembership',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='org_memberships', to=settings.AUTH_USER_MODEL)),
                ('org', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='memberships', to='stapel_auth.organization')),
                ('role', models.CharField(choices=[('member', 'Member'), ('admin', 'Admin')], default='member', max_length=20)),
                ('sso_subject_id', models.CharField(blank=True, help_text='NameID (SAML) or sub (OIDC) from IdP', max_length=500)),
                ('joined_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'db_table': 'sso_org_memberships', 'unique_together': {('user', 'org')}},
        ),
    ]
