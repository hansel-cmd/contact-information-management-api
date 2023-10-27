from django.db import models
from django.contrib.auth.models import AbstractUser
from phonenumber_field.modelfields import PhoneNumberField

def upload_to(instance, filename):
    return 'images/{filename}'.format(filename=filename)

# Create your models here.


class User(AbstractUser):
    profile = models.ImageField(upload_to=upload_to,null = True)
    phone_number = PhoneNumberField(max_length=13, null=True)
    is_email_confirmed = models.BooleanField(default=False)


class EmailConfirmationToken(models.Model):
    user = models.ForeignKey(
        User, default=None, on_delete=models.SET_NULL, null=True)


class Contact(models.Model):
    user = models.ForeignKey(
        User, default=None, on_delete=models.SET_NULL, null=True)
    profile = models.ImageField(upload_to=upload_to,null = True)
    first_name = models.CharField(max_length=30, null=False)
    last_name = models.CharField(max_length=30, null=False)
    phone_number = PhoneNumberField(max_length=13)
    house_no = models.CharField(max_length=10, null=True)
    street = models.CharField(max_length=100, null=True)
    city = models.CharField(max_length=100, null=True)
    province = models.CharField(max_length=100, null=True)
    zipcode = models.CharField(max_length=8, null=True)
    delivery_house_no = models.CharField(max_length=10, null=True)
    delivery_street = models.CharField(max_length=100, null=True)
    delivery_city = models.CharField(max_length=100, null=True)
    delivery_province = models.CharField(max_length=100, null=True)
    delivery_zipcode = models.CharField(max_length=8, null=True)
    is_favorite = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    is_emergency = models.BooleanField(default=False)
