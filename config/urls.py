from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.sitemaps.views import sitemap
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path
from django.views import defaults as default_views
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from .sitemaps import StaticViewSitemap
from .views import confirm_password, verify_email

sitemaps = {
    "static": StaticViewSitemap,
}

urlpatterns = [
    path("", TemplateView.as_view(template_name="pages/home.html"), name="home"),
    path("terms-and-condition/", TemplateView.as_view(template_name="legals/terms.html"), name="terms"),
    path("privacy-policy/", TemplateView.as_view(template_name="legals/privacy.html"), name="privacy"),
    # Your stuff: custom urls includes go here
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
if settings.DEBUG:
    # Static file serving when using Gunicorn + Uvicorn for local web socket development
    urlpatterns += staticfiles_urlpatterns()

# Dynamic app urls links
urlpatterns += [
    # User management
    path("users/", include("ezziee.users.urls", namespace="users")),
    path("accounts/", include("allauth.urls")),
    path('password-reset/confirm/<str:uidb64>/<str:token>/', view=confirm_password, name='confirm-password'),
    path('email/confirm/<str:key>/<str:email>/', view=verify_email, name='verify-email'),
]

# Admin Links
urlpatterns += [
    # Django Admin, use {% url 'admin:index' %}
    path('jet/', include('jet.urls', 'jet')),  # Django JET URLS
    path('jet/dashboard/', include('jet.dashboard.urls', 'jet-dashboard')),  # Django JET dashboard URLS
    # path('admin/', include('admin_honeypot.urls')),
    # path('backend/', include('admin_honeypot.urls')),
    # path('portal/', include('admin_honeypot.urls')),
    path(settings.ADMIN_URL, admin.site.urls),
]

# Required Links
urlpatterns += [
    # path('tinymce/', include('tinymce.urls')),
    path("sitemap.xml/", sitemap, kwargs={"sitemaps": sitemaps}, name="sitemap"),
    path("robots.txt/", TemplateView.as_view(template_name="robots.txt", content_type="text/plain"), name="robots"),
]



# API URLS
urlpatterns += [
    # API base url
    path("api/v1/", include("config.api_router")),
    # DRF auth token
    path("api/v1/schema/", SpectacularAPIView.as_view(), name="api-schema"),
    path(
        "api/v1/docs/",
        SpectacularSwaggerView.as_view(url_name="api-schema"),
        name="api-docs",
    ),
]

if settings.DEBUG:
    # This allows the error pages to be debugged during development, just visit
    # these url in browser to see how these error pages look like.
    urlpatterns += [
        path(
            "400/",
            default_views.bad_request,
            kwargs={"exception": Exception("Bad Request!")},
        ),
        path(
            "403/",
            default_views.permission_denied,
            kwargs={"exception": Exception("Permission Denied")},
        ),
        path(
            "404/",
            default_views.page_not_found,
            kwargs={"exception": Exception("Page not Found")},
        ),
        path("500/", default_views.server_error),
    ]
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar

        urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
