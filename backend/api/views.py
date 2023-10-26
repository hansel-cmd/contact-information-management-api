from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status

from .serializers import UserSerializer, SignUpSerializer
from .models import User

# Create your views here.


class IndexView(generics.GenericAPIView):
    def get(self, request, *args, **kwargs):
        return Response({"Hello": "World!"})


class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    lookup_field = 'pk'

    def post(self, request, *args, **kwargs):
        serializer = SignUpSerializer(data = request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        return Response(serializer.data, status = status.HTTP_200_OK)
