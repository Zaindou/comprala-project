from django.urls import path
from .views_auth import (
    UserCreate,
    CustomAuthTokenView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    ChangePasswordView,
    VerifyEmailView,
    ResendVerificationEmailView,
)

urlpatterns = [
    path("register/", UserCreate.as_view(), name="register"),
    path("login/", CustomAuthTokenView.as_view(), name="login"),
    path(
        "password-reset/",
        PasswordResetRequestView.as_view(),
        name="password_reset",
    ),
    path(
        "password-reset-confirm/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    path("verify-email/<str:token>/", VerifyEmailView.as_view(), name="verify_email"),
    path(
        "resend-verification-email/",
        ResendVerificationEmailView.as_view(),
        name="resend_verification_email",
    ),
]
