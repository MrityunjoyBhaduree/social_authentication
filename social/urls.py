from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    ProfileView,
    UserLogoutView,
    UserAccountDeleteAPIView,
    PasswordResetAPIView,
    PasswordChangeAPIView,
    # CountryIPAddressAPIView,
    # SocialLoginView,
    # ClientIDAPIView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    # path('social/login/', SocialLoginView.as_view(), name='social-login'),
    path('account-delete/', UserAccountDeleteAPIView.as_view(),
         name='delete'),
    path('password-reset/', PasswordResetAPIView.as_view(), name='reset'),
    path('password-change/', PasswordChangeAPIView.as_view(), name='change'),
    # path('get-country/', CountryIPAddressAPIView.as_view(), name='country-code'),
    # path('get-clientid/', ClientIDAPIView.as_view(), name='client-id')
]
