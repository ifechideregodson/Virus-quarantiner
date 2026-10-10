import hashlib

from django.core.validators import RegexValidator
from django.db import models, transaction
from django.utils import timezone

VERSION_RE = r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?\Z"
version_validator = RegexValidator(VERSION_RE, "Use a version like 1.2.0.")
sha256_validator = RegexValidator(
    r"^[0-9a-fA-F]{64}$", "Enter a 64-character SHA-256 hex digest."
)


class Release(models.Model):
    """A downloadable ShieldScan package (a ZIP with the scanner and its data)."""

    version = models.CharField(max_length=20, unique=True,
                               validators=[version_validator])
    released_at = models.DateTimeField(default=timezone.now)
    notes = models.TextField(blank=True)
    package = models.FileField(upload_to="releases/")
    sha256 = models.CharField(max_length=64, blank=True, editable=False)
    size_bytes = models.PositiveBigIntegerField(default=0, editable=False)
    is_current = models.BooleanField(default=False)
    download_count = models.PositiveIntegerField(default=0, editable=False)

    class Meta:
        ordering = ["-released_at", "-id"]

    def __str__(self):
        return f"ShieldScan {self.version}"

    @property
    def size_display(self):
        size = float(self.size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024

    def _fingerprint(self):
        """Return (sha256, size) of the package without closing a pending upload."""
        committed = getattr(self.package, "_committed", True)
        handle = (self.package.storage.open(self.package.name, "rb")
                  if committed else self.package.file)
        digest = hashlib.sha256()
        size = 0
        try:
            handle.seek(0)
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
            handle.seek(0)
        finally:
            if committed:
                handle.close()
        return digest.hexdigest(), size

    def save(self, *args, **kwargs):
        with transaction.atomic():
            # Hash a package that is new or was just replaced in the admin.
            pending_upload = not getattr(self.package, "_committed", True)
            if self.package and (not self.sha256 or pending_upload):
                self.sha256, self.size_bytes = self._fingerprint()
            super().save(*args, **kwargs)
            if self.is_current:
                Release.objects.exclude(pk=self.pk).filter(
                    is_current=True).update(is_current=False)


class Signature(models.Model):
    """A SHA-256 hash of a file known to be malicious."""

    sha256 = models.CharField(max_length=64, unique=True,
                              validators=[sha256_validator])
    name = models.CharField(max_length=120)
    notes = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.sha256[:12]})"

    def clean(self):
        # Runs before the uniqueness check, so "ABC..." and "abc..." collide.
        self.sha256 = (self.sha256 or "").strip().lower()

    def save(self, *args, **kwargs):
        self.sha256 = (self.sha256 or "").strip().lower()
        super().save(*args, **kwargs)
