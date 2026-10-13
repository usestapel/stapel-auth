import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0026_unique_sso_subject_per_org'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserSignup',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='signup_milestone', serialize=False, to=settings.AUTH_USER_MODEL)),
                ('registered_at', models.DateTimeField()),
                ('was_guest', models.BooleanField(default=False)),
            ],
            options={
                'verbose_name': 'User Signup',
                'verbose_name_plural': 'User Signups',
                'db_table': 'auth_user_signup',
            },
        ),
    ]
