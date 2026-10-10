from django.conf import settings
from django.db.models import F
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe, require_http_methods

from .forms import ScanForm
from .models import Release, Signature
from .services import (active_signature_map, engine_rules,
                       render_signatures_txt, scan_bytes)


@require_safe
def home(request):
    return render(request, "downloads/home.html", {
        "current": Release.objects.filter(is_current=True).first(),
        "signature_count": len(active_signature_map()),
    })


@require_safe
def releases(request):
    return render(request, "downloads/releases.html", {
        "releases": Release.objects.all(),
    })


@require_safe
def download_latest(request):
    current = Release.objects.filter(is_current=True).first()
    if current is None:
        raise Http404("No release has been published yet.")
    return redirect("downloads:download", version=current.version)


@require_safe
def download_release(request, version):
    release = get_object_or_404(Release, version=version)
    try:
        handle = release.package.storage.open(release.package.name, "rb")
    except FileNotFoundError:
        raise Http404("This package file is missing from the server.")
    Release.objects.filter(pk=release.pk).update(
        download_count=F("download_count") + 1)
    response = FileResponse(handle, as_attachment=True,
                            filename=f"shieldscan-{release.version}.zip",
                            content_type="application/zip")
    response["X-Release-SHA256"] = release.sha256
    return response


@require_safe
def signatures_txt(request):
    response = HttpResponse(render_signatures_txt(),
                            content_type="text/plain; charset=utf-8")
    response["Cache-Control"] = "public, max-age=300"
    return response


@never_cache
@require_http_methods(["GET", "POST"])
def scan(request):
    results = None
    if request.method == "POST":
        form = ScanForm(request.POST, request.FILES)
        if form.is_valid():
            signatures = active_signature_map()
            rules = engine_rules()
            results = [scan_bytes(f.name, f.read(), signatures, rules)
                       for f in form.cleaned_data["files"]]
    else:
        form = ScanForm()
    return render(request, "downloads/scan.html", {
        "form": form,
        "results": results,
        "max_files": settings.SCAN_MAX_FILES,
        "max_mb": settings.SCAN_MAX_FILE_BYTES // (1024 * 1024),
    })


@require_safe
def docs(request):
    return render(request, "downloads/docs.html", {
        "current": Release.objects.filter(is_current=True).first(),
    })
