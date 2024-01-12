from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class RewardsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ezziee.rewards"
    verbose_name = _("Rewards")

    def ready(self):
        try:
            import ezziee.rewards.signals  # noqa: F401
        except ImportError:
            pass
