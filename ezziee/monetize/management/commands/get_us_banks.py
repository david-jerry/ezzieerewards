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
    Retreives all operational banks in USA

    API Documentation:
        https://banks.data.fdic.gov/docs/
    """

    help = _("Adds or Updates all existing bank names in USA")

    def handle(self, *args, **kwargs):
        url = """https://banks.data.fdic.gov/api/institutions?filters=STALP%3AIA%20AND%20ACTIVE%3A1&fields=ZIP%2COFFDOM%2CCITY%2CCOUNTY%2CSTNAME%2CSTALP%2CNAME%2CACTIVE%2CCERT%2CCBSA%2CASSET%2CNETINC%2CDEP%2CDEPDOM%2CROE%2CROA%2CDATEUPDT%2COFFICES&sort_by=OFFICES&sort_order=DESC&limit=10&offset=0&format=json&download=false&filename=data_file"""
        headers = {
            "accept": "application/json",
        }

        res = requests.request("GET", url, headers=headers)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res['data']))

        if len(res["data"]) > 0:
            for response in res["data"]:
                try:
                    Banks.objects.create(
                        name=response['data']["NAME"],
                        slug=response['data']["NAME"].replace(' ', '_'),
                        lcode=response['data']["ID"],
                        code=response['data']["CERT"],
                        country_iso="US",
                    )
                    LOGGER.info(f"Successfully added {response['data']['name']}")
                except Exception as e:
                    LOGGER.error(e)
        else:
            LOGGER.error("US Banks Not Updated")

        self.stdout.write("Got all US Bank Details")
