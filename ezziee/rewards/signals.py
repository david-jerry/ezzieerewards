from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from ..utils.logger import LOGGER
from .models import RewardRequests
import requests

@receiver(post_save, sender=RewardRequests)
def update_artist_id(sender, instance, **kwargs):
    """
    Pass the username through the endpoint to get the user id
    and save it to the reward request
    """
    if not instance.ig_artist_id and instance.ig_artist_username:

        url = "https://instagram130.p.rapidapi.com/account-info"

        querystring = {"username":str(instance.ig_artist_username)}

        headers = {
            "X-RapidAPI-Key": settings.RAPIDAPI_KEY,
            "X-RapidAPI-Host": "instagram130.p.rapidapi.com"
        }

        response = requests.get(url, headers=headers, params=querystring)

        LOGGER.info(response.json())

        # if response.status_code == 200:
        #     instance.ig_artist_id = response.data.id
        #     instance.save(update_fields=['ig_artsit_id'])
