from django.db.models.signals import post_save
from django.dispatch import receiver


from ..monetize.models import UserBankAccount, Wallet
from ..utils.logger import LOGGER
from .models import User


@receiver(post_save, sender=User)
def update_related_user(sender, instance, created, **kwargs):
    """
    Update all relevant user related models to the main user model
    """
    if created:

        Wallet.objects.create(user=instance)
        UserBankAccount.objects.create(user=instance)
        LOGGER.info(
    """
RELATED MODEL SAVED
--------------------
Wallet and Userbank Account has been auto created on save
    """
        )
