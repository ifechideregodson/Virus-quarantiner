import hashlib
import re

from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError

from downloads.engine import shieldscan
from downloads.models import VERSION_RE, Release
from downloads.services import build_package


class Command(BaseCommand):
    help = ("Package the scanner, rules and current signatures into a release "
            "ZIP and publish it on the site.")

    def add_arguments(self, parser):
        parser.add_argument(
            "release_version", nargs="?", default=shieldscan.VERSION,
            help=f"Version to publish (default: {shieldscan.VERSION}, the "
                 "VERSION inside downloads/engine/shieldscan.py).")
        parser.add_argument("--notes", default="", help="Release notes.")
        parser.add_argument("--not-current", action="store_true",
                            help="Publish without making it the current release.")
        parser.add_argument("--force", action="store_true",
                            help="Replace an existing release with this version.")

    def handle(self, *args, **options):
        version = options["release_version"]
        if not re.match(VERSION_RE, version):
            raise CommandError(f"'{version}' is not a valid version like 1.2.0.")

        existing = Release.objects.filter(version=version).first()
        if existing and not options["force"]:
            raise CommandError(
                f"Version {version} already exists. Use --force to replace it.")

        payload = build_package(version)
        release = Release(
            version=version,
            notes=options["notes"],
            is_current=not options["not_current"],
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        release.package.save(f"shieldscan-{version}.zip",
                             ContentFile(payload), save=False)

        if existing:
            existing.package.delete(save=False)
            existing.delete()
        release.save()

        self.stdout.write(self.style.SUCCESS(
            f"Published ShieldScan {version} ({release.size_display}, "
            f"SHA-256 {release.sha256})"))
