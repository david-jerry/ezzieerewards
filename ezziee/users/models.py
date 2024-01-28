from django.contrib.auth.models import AbstractUser
from django.db.models import (
    CharField,
    # ManyToManyField,
    # ForeignKey,
    # CASCADE,
    # IntegerField,
    # DecimalField,
    # SlugField,
    # TextField,
    # OneToOneField,
    # FileField,
    # BooleanField,
    # DateField,
)
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

# from model_utils.models import TimeStampedModel
from encrypted_fields.fields import EncryptedCharField

# from ..utils.validators import image_validate_file_extension
# from ..utils.files import file_upload_path


class User(AbstractUser):
    """
    Default custom user model for ezziee.
    If adding fields that need to be filled at user signup,
    check forms.SignupForm and forms.SocialSignupForms accordingly.
    """

    # First and last name do not cover name patterns around the globe
    name = CharField(_("Name of User"), blank=True, max_length=255)
    phone = CharField(_("Phone Number"), blank=True, max_length=15)
    facebook_token = CharField(_("Facebook Graph Token"), blank=True, max_length=500)
    facebook_id = CharField(_("Facebook User ID"), blank=True, max_length=500)
    instagram_id = CharField(_("Instagram User ID"), blank=True, max_length=500)
    spotify_id = CharField(_("Spotify User ID"), blank=True, max_length=500)
    spotify_code = CharField(_("Spotify User Auth Code"), blank=True, max_length=500)
    spotify_access_token = CharField(_("Spotify User Access Token"), blank=True, max_length=500)
    spotify_refresh_token = CharField(_("Spotify User Refresh Token"), blank=True, max_length=500)
    youtube_id = CharField(_("Spotify User ID"), blank=True, max_length=500)
    youtube_code = CharField(_("Spotify User Auth Code"), blank=True, max_length=500)
    youtube_access_token = CharField(_("Spotify User Access Token"), blank=True, max_length=500)
    youtube_refresh_token = CharField(_("Spotify User Refresh Token"), blank=True, max_length=500)

    first_name = None  # type: ignore
    last_name = None  # type: ignore

    def get_absolute_url(self) -> str:
        """Get URL for user's detail view.

        Returns:
            str: URL for user detail.

        """
        return reverse("users:detail", kwargs={"username": self.username})











