from django.db.models import (
    CASCADE,
    Count,
    CharField,
    ManyToManyField,
    GenericIPAddressField,
)
from django.utils.translation import gettext_lazy as _

# from model_utils import FieldTracker
from model_utils.models import TimeStampedModel

class VisitorsIp(TimeStampedModel):
    """
    Model to store IP addresses of visitors.

    Attributes:
        - ip_address: GenericIPAddressField representing the visitor's IP address.
    """
    ip_address = GenericIPAddressField()

    class Meta:
        verbose_name = "Page Visitors Ip"
        verbose_name_plural = "Page Visitors Ips"

    def __str__(self):
        return f"IP: {self.ip_address}"

class PageAnalytics(TimeStampedModel):
    """
    Model to store analytics data for pages.

    Attributes:
        - page: CharField representing the page URL (unique).
        - visitors: ManyToManyField linking to VisitorsIp model to store IP addresses of visitors.

    Properties:
        - most_visited_page: Property returning the most visited page.
    """
    page = CharField(max_length=500, unique=True)
    visitors = ManyToManyField(VisitorsIp, on_delete=CASCADE, related_name="page_analytics")

    class Meta:
        verbose_name = "Page Analytics"
        verbose_name_plural = "Page Analytics"

    def __str__(self):
        return f"Analytics for {self.page}"

    @property
    def most_visited_page(self):
        """
        Property returning the most visited page.

        Returns:
            str: URL of the most visited page.
        """
        most_visited = PageAnalytics.objects.annotate(num_visitors=Count('visitors')).order_by('-num_visitors').first()
        return most_visited.page if most_visited else None
