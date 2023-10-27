from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from .models import User, Contact
from phonenumber_field.serializerfields import PhoneNumberField


class SignUpSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = [
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

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
        ]


class UserPasswordSerializer(serializers.ModelSerializer):
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


class UserPublicDataSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    first_name = serializers.CharField(read_only=True)
    last_name = serializers.CharField(read_only=True)


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
