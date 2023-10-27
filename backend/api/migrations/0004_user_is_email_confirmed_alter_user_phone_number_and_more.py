# Generated by Django 4.2.6 on 2023-10-26 12:43

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_email_confirmed',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='phone_number',
            field=phonenumber_field.modelfields.PhoneNumberField(max_length=13, null=True, region=None),
        ),
        migrations.CreateModel(
            name='EmailConfirmationToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Contacts',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile', models.CharField(max_length=255)),
                ('first_name', models.CharField(max_length=30)),
                ('last_name', models.CharField(max_length=30)),
                ('phone_number', phonenumber_field.modelfields.PhoneNumberField(max_length=13, region=None)),
                ('house_no', models.CharField(max_length=10, null=True)),
                ('street', models.CharField(max_length=100, null=True)),
                ('city', models.CharField(max_length=100, null=True)),
                ('province', models.CharField(max_length=100, null=True)),
                ('zipcode', models.CharField(max_length=8, null=True)),
                ('delivery_house_no', models.CharField(max_length=10, null=True)),
                ('delivery_street', models.CharField(max_length=100, null=True)),
                ('delivery_city', models.CharField(max_length=100, null=True)),
                ('delivery_province', models.CharField(max_length=100, null=True)),
                ('delivery_zipcode', models.CharField(max_length=8, null=True)),
                ('is_favorite', models.BooleanField(default=False)),
                ('is_blocked', models.BooleanField(default=False)),
                ('is_emergency', models.BooleanField(default=False)),
                ('user', models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]