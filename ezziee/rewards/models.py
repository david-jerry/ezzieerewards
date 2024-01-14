import json
from django.db.models import (
    CharField,
    ManyToManyField,
    ForeignKey,
    CASCADE,
    IntegerField,
    TextField,
    FileField,
    BooleanField,
    DateField,
)
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model

# from model_utils import FieldTracker
from model_utils.models import TimeStampedModel

from ..utils.validators import image_validate_file_extension
from ..utils.files import file_upload_path

User = get_user_model()


class RewardRequests(TimeStampedModel):
    """Encapsulates reward opportunities for users, engaging them in various social media actions.

    Attributes:
        title (CharField): The descriptive title of the reward, clearly conveying its purpose.
        image (FileField): Visually represents the reward, enhancing its appeal.
        active (BooleanField): Indicates whether the reward is currently available for users to claim.
        points (IntegerField): Specifies the number of points granted upon completion of the reward's actions.
        description (TextField): Provides a detailed explanation of the requirements and benefits of the reward.
        expiry (DateField): Marks the date when the reward becomes inactive, setting a timeframe for participation.

    Social Media Actions:
        fb_share_url (CharField): The URL for sharing a Facebook post, if applicable to the reward.
        fb_like_url (CharField): The URL for liking a Facebook post, if relevant to the reward.
        fb_comment_url (CharField): The URL for commenting on a Facebook post, if required for the reward.
        fb_follow_url (CharField): The URL for following a Facebook page or profile, if the reward involves such action.
        fb_post_id (CharField): The unique identifier of a specific Facebook post, if the reward is tied to it.

        ig_artist_username (CharField): The Instagram username of an artist, potentially relevant for Instagram-related rewards.
        ig_artist_id (CharField): The unique identifier of an artist on Instagram, used for targeted actions.
        ig_post_id (CharField): The unique identifier of a specific Instagram post, if the reward focuses on it.

        spotify_artist_id (CharField): The unique identifier of an artist on Spotify, for Spotify-related rewards.
        spotify_playlist_id (CharField): The unique identifier of a Spotify playlist, if the reward involves playlist engagement.
        spotify_album_id (CharField): The unique identifier of a Spotify album, if the reward targets album interactions.
        spotify_track_id (CharField): The unique identifier of a Spotify track, if the reward centers on track engagement.

    Methods:
        str(self): Returns a concise representation of the reward, including its title and active status.

    Meta:
        verbose_name (str): Provides a singular human-readable name for clarity in the admin interface.
        verbose_name_plural (str): Provides a plural human-readable name for consistency in admin interfaces.
        ordering (list): Specifies a default ordering of rewards based on their creation time, with newer rewards appearing first.
    """
    title = CharField(max_length=255, blank=False, null=False)
    subscribers = ManyToManyField(User, verbose_name=_("subscribers"), related_name="requests", blank=True)
    max_users = IntegerField(default=200)
    image = FileField(upload_to=file_upload_path.profile_image_upload_path, validators=[image_validate_file_extension], blank=True, null=True)
    active = BooleanField(default=True)
    description = TextField()
    expiry = DateField(blank=True, null=True)

    fb_share_url = CharField(max_length=500, blank=True, null=True)
    fb_like_url = CharField(max_length=500, blank=True, null=True)
    fb_comment_url = CharField(max_length=500, blank=True, null=True)
    fb_follow_url = CharField(max_length=500, blank=True, null=True)
    fb_post_id = CharField(max_length=500, blank=True, null=True)

    ig_artist_username = CharField(max_length=500, blank=True, null=True)
    ig_artist_id = CharField(max_length=500, blank=True, null=True)
    ig_post_id = CharField(max_length=500, blank=True, null=True)

    spotify_artist_id = CharField(max_length=500, blank=True, null=True)
    spotify_playlist_id = CharField(max_length=500, blank=True, null=True)
    spotify_album_id = CharField(max_length=500, blank=True, null=True)
    spotify_track_id = CharField(max_length=500, blank=True, null=True)

    youtube_channel_id = CharField(max_length=500, blank=True, null=True)

    paying = BooleanField(default=True)

    def calculate_reward_open(self):
        """
        Check if the reward is still open based on the number of users who have completed the tasks.
        """
        return self.subscribers.count() < self.max_users

    @property
    def is_reward_open(self):
        if not self.calculate_reward_open():
            self.active = False
            self.save(update_fields=['active'])
        else:
            self.active = True
            self.save(update_fields=['active'])
        return self.active

    # def get_actions(self):
    #     if self.actions.exists():
    #         return self.actions.all()
    #     return []

    # @property
    # def actions(self):
    #     return self.get_actions()



    def __str__(self):
        return f"{self.title} | Active: {self.active}"

    class Meta:
        verbose_name = _("Reward")
        verbose_name_plural = _("Rewards")
        ordering = ["-created"]


class RewardActions(TimeStampedModel):
    """This allows the user to perform certain prerequired actions: liking an artist post, commenting to an artist post
    following an artist

    Actions:
        Spotify: can perform only a follow action to an artist on spotify
        Instagram: can perform a like, follow
        Twitter: can perform only a follow action to an artist on twitter
        Soundcloud: can perform only a follow action to an artist on soundcloud
        Youtube: can perform a few actions like subscribe to a channel, comment on a channel's post


    Args:
        TimeStampedModel (_type_): An abstract model providing a created datetime field and a modified field to monitor the timestamp

    Methods:
        str(self): Returns a concise representation of the reward, including its action and platform action was performed on.
    """
    COMMENTS = "COMMENTS"
    LIKES = "LIKES"
    FOLLOWING = "FOLLOWING"
    ACTIONS = (
        (COMMENTS, COMMENTS),
        (LIKES, LIKES),
        (FOLLOWING, FOLLOWING),
    )

    FACEBOOK = "FACEBOOK"
    INSTAGRAM = "INSTAGRAM"
    SOUNDCLOUD = "SOUNDCLOUD"
    TWITTER = "TWITTER"
    SPOTIFY = "SPOTIFY"
    PLATFORM = (
        (FACEBOOK, FACEBOOK),
        (INSTAGRAM, INSTAGRAM),
        (SOUNDCLOUD, SOUNDCLOUD),
        (TWITTER, TWITTER),
        (SPOTIFY, SPOTIFY),
    )
    reward = ForeignKey(RewardRequests, on_delete=CASCADE, related_name="actions")
    action = CharField(max_length=25, choices=ACTIONS, default=COMMENTS)
    platform = CharField(max_length=25, choices=PLATFORM, default=FACEBOOK)

    def __str__(self):
        return f"{self.reward.title} | Action: {self.action} | Plt: {self.platform}"

    class Meta:
        verbose_name = _("Reward Action")
        verbose_name_plural = _("Rewards Actions")
        ordering = ["-modified"]

class CompletedActions(TimeStampedModel):
    user = ForeignKey(User, on_delete=CASCADE, related_name="completed_actions")
    tasks = ForeignKey(RewardRequests, on_delete=CASCADE, related_name="completed_actions")
    points = IntegerField(default=0)

    @property
    def completed_all_tasks(self):
        return self.points == self.tasks.actions.all().count()

    def __str__(self):
        return f"{self.tasks.title} | Completed: {self.points} of {self.tasks.actions.all().count()}"

    class Meta:
        verbose_name = _("Completed Action")
        verbose_name_plural = _("Completed Actions")
        ordering = ["-modified"]

