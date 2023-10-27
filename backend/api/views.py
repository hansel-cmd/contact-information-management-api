from django.contrib.auth.hashers import make_password
from django.db.models import Q
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser


from .serializers import UserSerializer, SignUpSerializer, ContactSerializer, UserPasswordSerializer
from .models import User, Contact
from . import mixins

# Create your views here.


class IndexView(generics.GenericAPIView):
    def get(self, request, *args, **kwargs):
        return Response({"Hello": "World!"})


class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    lookup_field = 'pk'

    def post(self, request, *args, **kwargs):
        serializer = SignUpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserView(
        mixins.PermissionAuthenticationMixin,
        generics.ListAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserSerializer
    lookup_field = 'pk'


class RetrieveUserView(
        mixins.PermissionAuthenticationMixin,
        generics.RetrieveAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserSerializer

    def get(self, request):
        try:
            user = User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateUserView(
        mixins.PermissionAuthenticationMixin,
        generics.UpdateAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserSerializer

    def put(self, request, *args, **kwargs):
        # Check if the data passed is valid.
        serializer = UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors)

        try:
            user = User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        updatable_fields = [
            'email', 'username', 'first_name', 'last_name', 'phone_number'
        ]

        for field in updatable_fields:
            if field in request.data:
                setattr(user, field, request.data.get(field))

        user.save()
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateUserPasswordView(
        mixins.PermissionAuthenticationMixin,
        generics.UpdateAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserPasswordSerializer

    def put(self, request, *args, **kwargs):
        # Check if the data [format] passed is valid.
        serializer = UserPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Do further validation here, i.e., matching passwords. Instead of doing it in the
        # serializer to avoid querying two times.
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        try:
            user = User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if new_password != confirm_password:
            return Response({"error": "New password and Confirm Password do not match."},
                            status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect."},
                            status=status.HTTP_400_BAD_REQUEST)

        user.password = make_password(new_password)
        user.save()

        serializer = UserPasswordSerializer(user)
        return Response({**serializer.data,
                         'username': request.user.username},
                        status=status.HTTP_200_OK)


class ListCreateContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.ListCreateAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    # We need parser_classes to parse a file upload when we handle POST with formData.
    parser_classes = (MultiPartParser, FormParser)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class RetrieveUpdateContactDetailView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.RetrieveUpdateAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    # We need parser_classes to parse a file upload when we handle POST with formData.
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, *args, **kwargs):
        id = kwargs.get('pk', None)
        if not id:
            return Response({"error": "Incorrect url."},
                            status=status.HTTP_404_NOT_FOUND)

        serializer = ContactSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            contact = Contact.objects.get(user=request.user, pk=id)
        except Contact.DoesNotExist:
            return Response({"error": "Contact does not exist."},
                            status=status.HTTP_404_NOT_FOUND)

        data = request.data
        errors = {}

        # Define the fields that can be updated
        updatable_fields = [
            'profile', 'first_name', 'last_name', 'phone_number', 'house_no', 'street',
            'city', 'province', 'zipcode', 'delivery_house_no', 'delivery_street',
            'delivery_city', 'delivery_province', 'delivery_zipcode'
        ]
        for field in updatable_fields:
            if field in data:
                setattr(contact, field, data[field])

        # Check and set boolean fields
        boolean_fields = ['is_favorite', 'is_emergency', 'is_blocked']
        for field in boolean_fields:
            if field in data:
                setattr(contact, field, bool(int(data[field])))

        # Check for invalid combinations
        if contact.is_favorite and contact.is_blocked:
            errors["is_favorite"] = "Cannot have a favorite contact to be a blocked contact."

        if contact.is_emergency and contact.is_blocked:
            errors["is_emergency"] = "Cannot have an emergency contact to be a blocked contact."

        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        contact.save()
        serializer = ContactSerializer(contact)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ListFavoriteContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.ListAPIView):
    queryset = Contact.objects.filter(is_favorite=True)
    serializer_class = ContactSerializer


class RetrieveUpdateFavoriteContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.RetrieveUpdateAPIView):
    """
    1. Retrieve a single favorite contact.
    2. Updates a single contact to be a favorite or not.
    """
    queryset = Contact.objects.filter(is_favorite=True)
    serializer_class = ContactSerializer

    def put(self, request, *args, **kwargs):
        id = kwargs.get('pk', None)
        if not id:
            return Response({"error": "Incorrect url."},
                            status=status.HTTP_404_NOT_FOUND)

        try:
            contact = Contact.objects.get(user=request.user, pk=id)
        except Contact.DoesNotExist:
            return Response({"error": "Contact does not exist."},
                            status=status.HTTP_404_NOT_FOUND)

        if contact.is_blocked:
            return Response({"error": "Cannot add a blocked contact to favorites."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Update contact to be favorite or unfavorite
        contact.is_favorite = not contact.is_favorite
        contact.save()

        serializer = ContactSerializer(contact)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ListEmergencyContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.ListAPIView):
    queryset = Contact.objects.filter(is_emergency=True)
    serializer_class = ContactSerializer


class RetrieveUpdateEmergencyContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.RetrieveUpdateAPIView):
    """
    1. Retrieve a single emergency contact.
    2. Updates a single contact to be an emergency or not.
    """
    queryset = Contact.objects.filter(is_emergency=True)
    serializer_class = ContactSerializer

    def put(self, request, *args, **kwargs):
        id = kwargs.get('pk', None)
        if not id:
            return Response({"error": "Incorrect url."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            contact = Contact.objects.get(user=request.user, pk=id)
        except Contact.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if contact.is_blocked:
            return Response({"error": "Cannot add a blocked contact to emergency contacts."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Update contact to be an emergency or non-emergency
        contact.is_emergency = not contact.is_emergency
        contact.save()

        serializer = ContactSerializer(contact)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ListBlockedContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.ListAPIView):
    queryset = Contact.objects.filter(is_blocked=True)
    serializer_class = ContactSerializer


class RetrieveUpdateBlockedContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.RetrieveUpdateAPIView):
    """
    1. Retrieve a single blocked contact.
    2. Updates a single contact to be blocked or not.
    """
    queryset = Contact.objects.filter(is_blocked=True)
    serializer_class = ContactSerializer

    def put(self, request, *args, **kwargs):
        id = kwargs.get('pk', None)
        if not id:
            return Response({"error": "Incorrect url."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            contact = Contact.objects.get(user=request.user, pk=id)
        except Contact.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if contact.is_favorite:
            return Response({"error": "Cannot add a favorite contact to blocked contacts."},
                            status=status.HTTP_400_BAD_REQUEST)

        if contact.is_emergency:
            return Response({"error": "Cannot add an emergency contact to blocked contacts."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Update contact to be an emergency or non-emergency
        contact.is_blocked = not contact.is_blocked
        contact.save()

        serializer = ContactSerializer(contact)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DestroyContactView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.DestroyAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer

    def destroy(self, request, *args, **kwargs):
        """
        Override destroy method so we can customize the Response.
        By default, destroy method returns HTTP_204_NO_CONTENT.
        """
        instance = self.get_object()
        serializer = ContactSerializer(instance)
        instance.delete()
        return Response(serializer.data, status=status.HTTP_200_OK)


class SearchContactsView(
        mixins.PermissionAuthenticationMixin,
        mixins.UserQuerySetMixin,
        generics.ListAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = ContactSerializer

    def get(self, request, *args, **kwargs):
        q = request.query_params.get('q')
        if not q:
            return super().get(request, *args, **kwargs)

        query = Q(first_name__icontains=q) | \
            Q(last_name__icontains=q) | \
            Q(phone_number__icontains=q) | \
            Q(house_no__icontains=q) | \
            Q(street__icontains=q) | \
            Q(city__icontains=q) | \
            Q(province__icontains=q) | \
            Q(zipcode__icontains=q) | \
            Q(delivery_house_no__icontains=q) | \
            Q(delivery_street__icontains=q) | \
            Q(delivery_city__icontains=q) | \
            Q(delivery_province__icontains=q) | \
            Q(delivery_zipcode__icontains=q)

        contact = Contact.objects.filter(query)
        serializer = ContactSerializer(contact, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
