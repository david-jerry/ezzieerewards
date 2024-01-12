from __future__ import annotations

import typing
from urllib.parse import urlencode

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.http import HttpRequest
from django.urls import reverse

if typing.TYPE_CHECKING:
    from allauth.socialaccount.models import SocialLogin
    from ezziee.users.models import User


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request: HttpRequest) -> bool:
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)

    def get_email_confirmation_url(self, request, emailconfirmation):
        # Add custom parameters to the URL
        kwargs = {
            "key": emailconfirmation.key,
            "email": emailconfirmation.email_address.email,
        }
        url = reverse(
            "account_confirm_email", args=[emailconfirmation.key]
        ) + f"?{urlencode(kwargs)}"
        return url


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request: HttpRequest, sociallogin: SocialLogin) -> bool:
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)

    def populate_user(self, request: HttpRequest, sociallogin: SocialLogin, data: dict[str, typing.Any]) -> User:
        """
        Populates user information from social provider info.

        See: https://django-allauth.readthedocs.io/en/latest/advanced.html?#creating-and-populating-user-instances
        """
        user = super().populate_user(request, sociallogin, data)
        if not user.name:
            if name := data.get("name"):
                user.name = name
            elif first_name := data.get("first_name"):
                user.name = first_name
                if last_name := data.get("last_name"):
                    user.name += f" {last_name}"
        return user
