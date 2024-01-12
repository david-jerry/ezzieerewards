from __future__ import absolute_import

from django.contrib.sitemaps import Sitemap
from django.urls import reverse


class StaticViewSitemap(Sitemap):
    def items(self):
        return ["home", "terms", "privacy", "sitemap"]

    def location(self, item):
        return reverse(item)
