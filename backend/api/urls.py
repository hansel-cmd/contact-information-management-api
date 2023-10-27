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
    path('user/me/', views.RetrieveUserView.as_view(), name = 'user'),
    path('user/update/', views.UpdateUserView.as_view(), name = 'user-update'),
    path('user/update-account/', views.UpdateUserView.as_view(), name = 'user-update-account'),
    path('user/update-password/', views.UpdateUserPasswordView.as_view(), name = 'user-update-password'),

    path('contacts/', views.ListCreateContactView.as_view(), name = 'contacts'),
    path('contact/<int:pk>/', views.ContactDetailView.as_view(), name = 'contact'),
    path('create-contact/', views.ListCreateContactView.as_view(), name = 'create-contact'),

    path('favorite-contacts/', views.ListFavoriteContactView.as_view(), name = 'favorite-contacts'),
    path('favorite-contact/<int:pk>/', views.RetrieveUpdateFavoriteContact.as_view(), name = 'favorite-contact'),

    path('emergency-contacts/', views.ListEmergencyContactView.as_view(), name = 'emergency-contacts'),
    path('emergency-contact/<int:pk>/', views.RetrieveUpdateEmergencyContact.as_view(), name = 'emergency-contact'),

    path('blocked-contacts/', views.ListBlockedContactView.as_view(), name = 'blocked-contacts'),
    path('blocked-contact/<int:pk>/', views.RetrieveUpdateBlockedContact.as_view(), name = 'blocked-contact'),
    
    path('delete-contact/<int:pk>/', views.DestroyContactView.as_view(), name = 'delete-contact'),
]
