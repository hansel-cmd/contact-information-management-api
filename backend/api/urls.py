from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views

urlpatterns = [
    path('', views.IndexView.as_view(), name = 'index'),
    path('template/', views.test, name = 'template'),
    path('login/', views.CustomTokenObtainPairView.as_view(), name='token-obtain-pair'), # serves as the login feature
    path('login/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('signup/', views.SignupView.as_view(), name = 'signup'),
    path('send-email-confirmation/', views.SendEmailConfirmationView.as_view(), name='send-email-confirmation'),
    path('verify-email-confirmation/', views.VerifyEmailConfirmationTokenView.as_view(), name='verify-email-confirmation'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('unique-username/', views.UniqueUsernameView.as_view(), name = 'unique-username'),
    path('unique-email/', views.UniqueEmailView.as_view(), name = 'unique-email'),
    path('is-email-existing/', views.IsEmailExistingView.as_view(), name = 'is-email-existing'),
    path('generate-forgot-password-token/', views.GenerateForgotPasswordTokenView.as_view(), name='generate-forgot-password-token'),
    path('validate-forgot-password-token/', views.GenerateForgotPasswordTokenView.as_view(), name='validate-forgot-password-token'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),

    path('users/', views.UserListView.as_view(), name = 'users'),
    path('user/me/', views.RetrieveUserView.as_view(), name = 'user'),
    path('user/update/', views.UpdateUserView.as_view(), name = 'user-update'),
    path('user/update-account/', views.UpdateUserView.as_view(), name = 'user-update-account'),
    path('user/update-password/', views.UpdateUserPasswordView.as_view(), name = 'user-update-password'),
    path('user/update-email/', views.UpdateUserEmailView.as_view(), name = 'user-update-email'),
    path('users/delete/<int:pk>', views.DestroyUserView.as_view(), name = 'delete-user'),

    path('search-contacts/', views.SearchContactsView.as_view(), name = 'search-contacts'),

    path('contacts/', views.ListCreateContactView.as_view(), name = 'contacts'),
    path('contact/<int:pk>/', views.RetrieveUpdateContactDetailView.as_view(), name = 'contact'),
    path('contact/update/<int:pk>/', views.RetrieveUpdateContactDetailView.as_view(), name = 'update-contact'),
    path('create-contact/', views.ListCreateContactView.as_view(), name = 'create-contact'),
    path('check-phone-number/', views.CheckPhoneNumberView.as_view(), name = 'check-phone-number'),

    path('favorite-contacts/', views.ListFavoriteContactView.as_view(), name = 'favorite-contacts'),
    path('favorite-contact/<int:pk>/', views.RetrieveUpdateFavoriteContactView.as_view(), name = 'favorite-contact'),

    path('emergency-contacts/', views.ListEmergencyContactView.as_view(), name = 'emergency-contacts'),
    path('emergency-contact/<int:pk>/', views.RetrieveUpdateEmergencyContactView.as_view(), name = 'emergency-contact'),

    path('blocked-contacts/', views.ListBlockedContactView.as_view(), name = 'blocked-contacts'),
    path('blocked-contact/<int:pk>/', views.RetrieveUpdateBlockedContactView.as_view(), name = 'blocked-contact'),
    
    path('delete-contact/<int:pk>/', views.DestroyContactView.as_view(), name = 'delete-contact'),
]
