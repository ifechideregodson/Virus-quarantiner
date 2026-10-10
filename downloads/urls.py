from django.urls import path

from . import views

app_name = "downloads"

urlpatterns = [
    path("", views.home, name="home"),
    path("releases/", views.releases, name="releases"),
    path("download/latest/", views.download_latest, name="download_latest"),
    path("download/<str:version>/", views.download_release, name="download"),
    path("signatures.txt", views.signatures_txt, name="signatures"),
    path("scan/", views.scan, name="scan"),
    path("docs/", views.docs, name="docs"),
]
