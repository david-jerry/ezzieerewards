from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class ModetizeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ezziee.monetize"
    verbose_name = _("monetize")
