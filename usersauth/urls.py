from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path
from .views import SignUp,LoginView, AccountActivation, PasswordReset,PasswordResetVerify, PasswordChange
urlpatterns = [
    
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('signup/',SignUp.as_view()),
    path('login/',LoginView.as_view()),
    path('active-code/', AccountActivation.as_view()),
    path('password-reset/',PasswordReset.as_view()),
    path('password-reset-verify/', PasswordResetVerify.as_view()),
    path('password-change/', PasswordChange.as_view()),
    
]