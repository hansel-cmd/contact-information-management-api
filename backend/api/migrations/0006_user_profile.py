# Generated by Django 4.2.6 on 2023-10-27 11:28

import api.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_contact_delete_contacts'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='profile',
            field=models.ImageField(null=True, upload_to=api.models.upload_to),
        ),
    ]
