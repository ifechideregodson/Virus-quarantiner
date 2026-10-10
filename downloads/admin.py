from django.contrib import admin

from .models import Release, Signature


@admin.register(Release)
class ReleaseAdmin(admin.ModelAdmin):
    list_display = ("version", "released_at", "is_current", "size_display",
                    "download_count", "short_sha")
    list_filter = ("is_current",)
    search_fields = ("version", "notes")
    readonly_fields = ("sha256", "size_bytes", "download_count")
    fields = ("version", "released_at", "package", "is_current", "notes",
              "sha256", "size_bytes", "download_count")

    @admin.display(description="SHA-256")
    def short_sha(self, obj):
        return obj.sha256[:16] + "..." if obj.sha256 else ""


@admin.register(Signature)
class SignatureAdmin(admin.ModelAdmin):
    list_display = ("name", "short_sha", "active", "added_at")
    list_filter = ("active",)
    search_fields = ("name", "sha256", "notes")
    actions = ["activate", "deactivate"]

    @admin.display(description="SHA-256")
    def short_sha(self, obj):
        return obj.sha256[:16] + "..."

    @admin.action(description="Switch on selected signatures")
    def activate(self, request, queryset):
        queryset.update(active=True)

    @admin.action(description="Switch off selected signatures")
    def deactivate(self, request, queryset):
        queryset.update(active=False)
