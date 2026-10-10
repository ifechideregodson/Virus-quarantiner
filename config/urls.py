from django.contrib import admin
from django.urls import include, path

admin.site.site_header = "ShieldScan administration"
admin.site.site_title = "ShieldScan admin"
admin.site.index_title = "Releases and signatures"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("downloads.urls")),
]
