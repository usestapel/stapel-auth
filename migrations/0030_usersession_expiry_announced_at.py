from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0029_sessionaccesstoken'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='usersession',
            name='expiry_announced_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddIndex(
            model_name='usersession',
            index=models.Index(condition=models.Q(('expiry_announced_at__isnull', True), ('is_revoked', False)), fields=['expires_at'], name='user_sessions_unannounced_exp'),
        ),
    ]
