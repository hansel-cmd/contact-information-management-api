from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from .models import *
from phonenumber_field.serializerfields import PhoneNumberField


class UserPublicDataSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    first_name = serializers.CharField(read_only=True)
    last_name = serializers.CharField(read_only=True)


class SignUpSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = [
            'id',
            'first_name',
            'last_name',
            'email',
            'username',
            'password',
            'confirm_password'
        ]

    def validate(self, data):
        if 'password' in data and 'confirm_password' in data and data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def validate_email(self, value):
        user = User.objects.filter(email=value)
        if user.exists():
            raise serializers.ValidationError(f"{value} is already taken.")
        return value

    def validate_username(self, value):
        user = User.objects.filter(username=value)
        if user.exists():
            raise serializers.ValidationError(f"{value} is already taken.")
        return value

    """
    When the view api calls the serializer.save(), this will be executed.
    We need to pop the confirm_password field because it's not part of the
    original User model we have. We also have to hash our password before
    storing into the database.
    """

    def create(self, validated_data):
        validated_data.pop('confirm_password', None)

        # Hash the password using make_password
        validated_data['password'] = make_password(validated_data['password'])

        instance = User.objects.create(**validated_data)
        return instance


class UserSerializer(serializers.ModelSerializer):
    """
    The fields are optional when updating. If there is no value
    provided in the field, the current value will be used.
    """
    username = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    phone_number = PhoneNumberField(required=False)
    is_email_confirmed = serializers.BooleanField(required=False)
    profile = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = [
            'id',
            'profile',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'is_email_confirmed'
        ]


class UserPasswordSerializer(serializers.ModelSerializer):
    """Changing of Password via Settings"""
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = [
            'id',
            'old_password',
            'new_password',
            'confirm_password',
        ]


class ContactSerializer(serializers.ModelSerializer):
    profile = serializers.ImageField(required=False)
    user = UserPublicDataSerializer(read_only=True)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    phone_number = PhoneNumberField(required=False)

    class Meta:
        model = Contact
        fields = [
            'user',
            'id',
            'profile',
            'first_name',
            'last_name',
            'phone_number',
            'house_no',
            'street',
            'city',
            'province',
            'zipcode',
            'delivery_house_no',
            'delivery_street',
            'delivery_city',
            'delivery_province',
            'delivery_zipcode',
            'is_favorite',
            'is_blocked',
            'is_emergency'
        ]


class CustomContactSerializer(serializers.ModelSerializer):
    profile = serializers.ImageField(required=False)
    user = UserPublicDataSerializer(read_only=True)
    firstName = serializers.CharField(source='first_name', required=False)
    lastName = serializers.CharField(source='last_name', required=False)
    phoneNumber = PhoneNumberField(source='phone_number', required=False)
    deliveryAddress = serializers.SerializerMethodField()
    billingAddress = serializers.SerializerMethodField()
    isFavorite = serializers.BooleanField(source="is_favorite", required=False)
    isBlocked = serializers.BooleanField(source="is_blocked", required=False)
    isEmergency = serializers.BooleanField(
        source="is_emergency", required=False)

    class Meta:
        model = Contact
        fields = [
            'user',
            'id',
            'profile',
            'firstName',
            'lastName',
            'phoneNumber',
            'house_no',
            'street',
            'city',
            'province',
            'zipcode',
            'deliveryAddress',
            'billingAddress',
            'isFavorite',
            'isBlocked',
            'isEmergency'
        ]

    def get_deliveryAddress(self, instance):
        return {
            'houseNo': instance.delivery_house_no,
            'street': instance.delivery_street,
            'city': instance.delivery_city,
            'province': instance.delivery_province,
            'zipCode': instance.delivery_zipcode,
        }

    def get_billingAddress(self, instance):
        return {
            'houseNo': instance.house_no,
            'street': instance.street,
            'city': instance.city,
            'province': instance.province,
            'zipCode': instance.zipcode,
        }


class EmailConfirmationTokenSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField()

    class Meta:
        model = EmailConfirmationToken
        fields = [
            'user_id',
            'token'
        ]

    def validate(self, data):
        user_id = data.get('user_id', None)
        token = data.get('token', None)
        try:
            EmailConfirmationToken.objects.get(
                user_id=user_id, token=token, is_expired=False)
        except EmailConfirmationToken.DoesNotExist:
            raise serializers.ValidationError(
                "The User does not exist or Email Confirmation Code is invalid/expired.")

        return data


class ForgotPasswordTokenSerializer(serializers.ModelSerializer):
    email = serializers.CharField()

    class Meta:
        model = ForgotPasswordToken
        fields = [
            'email',
            'token'
        ]

    def validate(self, data):
        email = data.get('email', None)
        token = data.get('token', None)
        try:
            ForgotPasswordToken.objects.get(
                user__email=email, token=token, is_expired=False)
        except ForgotPasswordToken.DoesNotExist:
            raise serializers.ValidationError(
                "The User does not exist or Forgot Password Code is invalid/expired.")

        return data


class ResetPasswordSerializer(serializers.ModelSerializer):
    """Resetting of a Forgotten Password"""
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = [
            'email',
            'password',
            'confirm_password',
        ]

    def validate(self, data):
        if 'password' in data and 'confirm_password' in data and data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
