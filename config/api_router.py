from django.conf import settings
from django.urls import path

from rest_framework.routers import DefaultRouter, SimpleRouter
from dj_rest_auth.registration.views import VerifyEmailView
from dj_rest_auth.views import LogoutView, PasswordResetConfirmView

from ezziee.users.api.views import (
    # CustomObtainJWTToken,
    RegisterViewset,
    UserLoginViewset,
    LogoutViewset,
    UserViewSet,

    VerifyEmailViewset,

    PasswordChangeViewset,
    PasswordResetViewset,
    PasswordResetConfirmViewset,
    ResendEmailVerificationViewset,

    # TokenObtainPairViewset,
    TokenRefreshViewset,

    InstagramConnectViewset,
    SpotifyConnectViewset,
    SpotifyCallback,

    email_confirm_redirect,
    password_reset_confirm_redirect
)

from ezziee.monetize.api.views import (
    BanksViewSet,
    UserBankAccountViewSet,
)

from ezziee.rewards.api.views import (
    RewardActionsViewset,
    RewardViewset,
)

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("auth/registration", RegisterViewset, basename="register")
router.register("auth/login", UserLoginViewset, basename="login")
# router.register("auth/logout", LogoutViewset, basename="logout")
# router.register("auth/token", TokenObtainPairViewset, basename="token")
router.register("auth/token-refresh", TokenRefreshViewset, basename="token-get_current_site(context_manager.request_refresh")
router.register("auth/password/change", PasswordChangeViewset, basename="account_password_change")
router.register("auth/password/reset", PasswordResetViewset, basename="account_password_reset")
router.register("auth/password/reset/confirm", PasswordResetConfirmViewset, basename="password_reset_confirm")
router.register("auth/registration/resend-email-verification", ResendEmailVerificationViewset, basename="resend_email_verification")
# router.register("auth/registration/verify-email", VerifyEmailViewset, basename="account_verify_email")


router.register("monetize/banks", BanksViewSet, basename="bank")
router.register("monetize/bank-accounts", UserBankAccountViewSet, basename="bankaccount")

router.register("users/connect/instagram", InstagramConnectViewset, basename="instagram")
router.register("users/connect/spotify/userid", SpotifyConnectViewset, basename="spotify")
router.register("users", UserViewSet, basename="user")


router.register("rewards/posts", RewardViewset, basename="reward")
router.register("rewards/tasks", RewardActionsViewset, basename="rewardtask")

app_name = "api"
urlpatterns = router.urls

urlpatterns += [
    path("users/connect/spotify/callback", SpotifyCallback.as_view(), name="spotifycallback"),
    path("auth/logout/", LogoutViewset.as_view(), name="account_logout"),
    path("auth/registration/verify-email/", VerifyEmailViewset.as_view(), name="account_verify_email"),
    path("auth/registration/account-confirm-email/<str:key>/", email_confirm_redirect, name="account_confirm_email"),
    path(
        "auth/password/reset/confirm/<str:uidb64>/<str:token>/",
        password_reset_confirm_redirect,
        name="password_reset_confirm",
    ),
    # path("auth/password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]
