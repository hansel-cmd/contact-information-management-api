from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views

urlpatterns = [
    path('', views.IndexView.as_view(), name = 'index'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'), # serves as the login feature
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('signup/', views.SignupView.as_view(), name = 'signup'),
    path('users/', views.UserView.as_view(), name = 'users'),
    path('contacts/', views.ListCreateContactView.as_view(), name = 'contacts'),
    path('create-contact/', views.ListCreateContactView.as_view(), name = 'create-contact'),
]
