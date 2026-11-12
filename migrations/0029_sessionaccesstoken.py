from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0028_signupattribution_landing_ref'),
    ]

    operations = [
        migrations.CreateModel(
            name='SessionAccessToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('jti', models.CharField(max_length=64, unique=True)),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='access_tokens', to='authentication.usersession')),
            ],
            options={
                'db_table': 'user_session_access_tokens',
            },
        ),
    ]
