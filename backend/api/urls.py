from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views

urlpatterns = [
    path('', views.IndexView.as_view(), name = 'index'),
    path('signup/', views.SignupView.as_view(), name = 'signup'),
    path('users/', views.UserView.as_view(), name = 'users'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
