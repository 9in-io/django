from django.contrib import admin

from .models import NineIdentity


@admin.register(NineIdentity)
class NineIdentityAdmin(admin.ModelAdmin):
    list_display = ("sub", "user", "issuer", "created_at", "last_login_at")
    list_filter = ("issuer",)
    search_fields = ("sub",)
    raw_id_fields = ("user",)
    readonly_fields = ("created_at", "last_login_at")
    date_hierarchy = "created_at"
