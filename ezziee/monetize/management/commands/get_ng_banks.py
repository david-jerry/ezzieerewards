from __future__ import annotations

import pprint

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.translation import gettext_lazy as _

# from requests_html import HTMLSession
from ....utils.logger import LOGGER

from ...models import Banks


class Command(BaseCommand):
    """
    Retreives all operational banks in Nigeria
    """

    help = _("Adds or Updates all existing bank names in Nigeria")

    def handle(self, *args, **kwargs):
        url = "https://api.paystack.co/bank"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        }
        data = {"country": "nigeria", "use_cursor": True, "perPage": 100}

        res = requests.request("GET", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            for response in res["data"]:
                try:
                    Banks.objects.create(
                        name=response["name"],
                        slug=response["slug"],
                        lcode=response["longcode"],
                        code=response["code"],
                        country_iso="NG",
                    )
                    LOGGER.info(f"Successfully added {response['name']}")
                except Exception as e:
                    LOGGER.error(e)
        else:
            LOGGER.error("Nigerian Banks Not Updated")

        self.stdout.write("Got all Nigeria Bank Details")
