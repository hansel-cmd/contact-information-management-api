from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from .models import User, Contact

class SignUpSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only = True, required = True)
    first_name = serializers.CharField(required = True)
    last_name = serializers.CharField(required = True)
    email = serializers.EmailField(required = True)

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
        user = User.objects.filter(email = value)
        if user.exists():
            raise serializers.ValidationError(f"{value} is already taken.")
        return value

    def validate_username(self, value):
        user = User.objects.filter(username = value)
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

class UserPublicDataSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only = True)
    username = serializers.CharField(read_only = True)
    first_name = serializers.CharField(read_only = True)
    last_name = serializers.CharField(read_only = True)


class CreateContactSerializer(serializers.ModelSerializer):
    profile = serializers.ImageField(required=False)
    user = UserPublicDataSerializer(read_only = True)

    class Meta:
        model = Contact
        fields = [
            'user',
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