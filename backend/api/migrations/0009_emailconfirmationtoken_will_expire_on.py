# Generated by Django 4.2.6 on 2023-11-03 08:18

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_emailconfirmationtoken_created_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='emailconfirmationtoken',
            name='will_expire_on',
            field=models.DateTimeField(default=datetime.datetime(2023, 11, 3, 16, 18, 43, 850926)),
            preserve_default=False,
        ),
    ]