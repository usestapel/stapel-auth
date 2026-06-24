from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0004_authenticatorchangerequest'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserSession',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('jti', models.CharField(db_index=True, max_length=64, unique=True)),
                ('device_name', models.CharField(blank=True, max_length=150)),
                ('user_agent', models.TextField(blank=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_used_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('is_revoked', models.BooleanField(db_index=True, default=False)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='sessions',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'db_table': 'user_sessions',
                'ordering': ['-last_used_at'],
                'indexes': [
                    models.Index(fields=['user', 'is_revoked'], name='usersession_user_revoked_idx'),
                ],
            },
        ),
        migrations.CreateModel(
            name='TOTPDevice',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('secret', models.CharField(max_length=64)),
                ('is_active', models.BooleanField(default=False)),
                ('backup_codes', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('confirmed_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='totp_device',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'db_table': 'totp_devices',
            },
        ),
    ]
