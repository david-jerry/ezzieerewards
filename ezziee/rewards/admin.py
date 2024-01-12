from django.contrib import admin

from .models import CompletedActions, RewardActions, RewardRequests

admin.site.register(RewardActions)
admin.site.register(RewardRequests)
admin.site.register(CompletedActions)
