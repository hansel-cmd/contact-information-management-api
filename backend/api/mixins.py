from .models import User

from rest_framework import generics


class UserQuerySetMixin(generics.GenericAPIView):
    user_field = 'user' # to change this, go to the class that uses this mixin, and overwrite it there
    def get_queryset(self):
        lookup_data = {}
        lookup_data[self.user_field] = self.request.user
        qs = super().get_queryset()
        return qs.filter(**lookup_data)