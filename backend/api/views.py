from django.contrib.auth.hashers import make_password
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication

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


class UserView(generics.ListAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserSerializer
    lookup_field = 'pk'

    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]


class ListCreateContactView(mixins.UserQuerySetMixin, generics.ListCreateAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    # We need parser_classes to parse a file upload when we handle POST with formData.
    parser_classes = (MultiPartParser, FormParser)

    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ContactDetailView(mixins.UserQuerySetMixin, generics.RetrieveAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer

    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]


class ListFavoriteContactView(mixins.UserQuerySetMixin, generics.ListAPIView):
    queryset = Contact.objects.filter(is_favorite=True)
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]


class RetrieveUpdateFavoriteContact(mixins.UserQuerySetMixin, generics.RetrieveUpdateAPIView):
    """
    1. Retrieve a single favorite contact.
    2. Updates a single contact to be a favorite or not.
    """
    queryset = Contact.objects.filter(is_favorite=True)
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

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


class ListEmergencyContactView(mixins.UserQuerySetMixin, generics.ListAPIView):
    queryset = Contact.objects.filter(is_emergency=True)
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]


class RetrieveUpdateEmergencyContact(mixins.UserQuerySetMixin, generics.RetrieveUpdateAPIView):
    """
    1. Retrieve a single emergency contact.
    2. Updates a single contact to be an emergency or not.
    """
    queryset = Contact.objects.filter(is_emergency=True)
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

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


class ListBlockedContactView(mixins.UserQuerySetMixin, generics.ListAPIView):
    queryset = Contact.objects.filter(is_blocked=True)
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]


class RetrieveUpdateBlockedContact(mixins.UserQuerySetMixin, generics.RetrieveUpdateAPIView):
    """
    1. Retrieve a single blocked contact.
    2. Updates a single contact to be blocked or not.
    """
    queryset = Contact.objects.filter(is_blocked=True)
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

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


class DestroyContactView(mixins.UserQuerySetMixin, generics.DestroyAPIView):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

    """
    Override destroy method so we can customize the Response.
    By default, destroy method returns HTTP_204_NO_CONTENT.
    """

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = ContactSerializer(instance)
        instance.delete()
        return Response(serializer.data, status=status.HTTP_200_OK)


class RetrieveUserView(generics.RetrieveAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

    def get(self, request):
        try:
            user = User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateUserView(generics.UpdateAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

    def put(self, request, *args, **kwargs):
        # Check if the data passed is valid.
        serializer = UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors)

        try:
            user = User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.data.get('email'):
            user.email = request.data.get('email')
        if request.data.get('username'):
            user.username = request.data.get('username')
        if request.data.get('first_name'):
            user.first_name = request.data.get('first_name')
        if request.data.get('last_name'):
            user.last_name = request.data.get('last_name')
        if request.data.get('phone_number'):
            user.phone_number = request.data.get('phone_number')

        user.save()
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateUserPasswordView(generics.UpdateAPIView):
    queryset = User.objects.filter(is_staff=False)
    serializer_class = UserPasswordSerializer
    authentication_classes = [
        JWTAuthentication,
        # TokenAuthentication
    ]
    permission_classes = [
        permissions.IsAuthenticated
    ]

    def put(self, request, *args, **kwargs):
        # Check if the data [format] passed is valid.
        serializer = UserPasswordSerializer(
            data=request.data, context={'request': request})
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
