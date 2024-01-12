from django.conf import settings


def allauth_settings(request):
    """Expose some settings from django-allauth in templates."""
    return {
        "ACCOUNT_ALLOW_REGISTRATION": settings.ACCOUNT_ALLOW_REGISTRATION,
        "fb_app_id": settings.APP_ID,
        "fb_api_version": settings.API_VERSION
    }
