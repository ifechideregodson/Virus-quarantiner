import hashlib
import io
import tempfile
import zipfile
from io import StringIO

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.urls import reverse

from .engine import shieldscan
from .models import Release, Signature
from .services import EICAR_SHA256, build_package

EICAR = shieldscan.EICAR


def upload(name, data):
    return SimpleUploadedFile(name, data)


class MediaTestCase(TestCase):
    """Runs each test class with release files in a throwaway folder."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        cls._override = override_settings(MEDIA_ROOT=cls._tmp.name)
        cls._override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._override.disable()
        cls._tmp.cleanup()
        super().tearDownClass()


class PageTests(TestCase):
    def test_public_pages_load(self):
        for name in ("home", "releases", "scan", "docs", "signatures"):
            with self.subTest(page=name):
                self.assertEqual(
                    self.client.get(reverse(f"downloads:{name}")).status_code, 200)

    def test_admin_login_page_loads(self):
        self.assertEqual(self.client.get("/admin/login/").status_code, 200)

    def test_latest_download_is_404_without_a_release(self):
        response = self.client.get(reverse("downloads:download_latest"))
        self.assertEqual(response.status_code, 404)

    def test_unknown_release_is_404(self):
        response = self.client.get(reverse("downloads:download", args=["9.9.9"]))
        self.assertEqual(response.status_code, 404)

    def test_home_shows_message_when_no_release(self):
        self.assertContains(self.client.get(reverse("downloads:home")),
                            "No release has been published yet")


class ReleaseTests(MediaTestCase):
    def publish(self, version="9.9.9", **options):
        call_command("build_release", version, stdout=StringIO(), **options)
        return Release.objects.get(version=version)

    def test_build_release_publishes_a_verifiable_package(self):
        release = self.publish("9.9.9", notes="test release")
        self.assertTrue(release.is_current)
        self.assertEqual(len(release.sha256), 64)

        response = self.client.get(reverse("downloads:download", args=["9.9.9"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn("shieldscan-9.9.9.zip", response["Content-Disposition"])
        body = b"".join(response.streaming_content)
        self.assertEqual(hashlib.sha256(body).hexdigest(), release.sha256)
        self.assertEqual(len(body), release.size_bytes)

        names = zipfile.ZipFile(io.BytesIO(body)).namelist()
        for expected in ("shieldscan.py", "rules.txt", "README.txt",
                         "signatures.txt"):
            self.assertIn(f"shieldscan-9.9.9/{expected}", names)

    def test_download_counter_increments(self):
        release = self.publish()
        url = reverse("downloads:download", args=[release.version])
        for _ in range(2):
            b"".join(self.client.get(url).streaming_content)
        release.refresh_from_db()
        self.assertEqual(release.download_count, 2)

    def test_packaged_scanner_is_the_engine_file(self):
        release = self.publish()
        with zipfile.ZipFile(release.package.path) as archive:
            packed = archive.read("shieldscan-9.9.9/shieldscan.py")
        with open(shieldscan.__file__, "rb") as handle:
            self.assertEqual(packed, handle.read())

    def test_packaged_signatures_include_database_entries(self):
        Signature.objects.create(sha256="a" * 64, name="Test sample")
        release = self.publish()
        with zipfile.ZipFile(release.package.path) as archive:
            text = archive.read("shieldscan-9.9.9/signatures.txt").decode()
        self.assertIn("a" * 64, text)
        self.assertIn(EICAR_SHA256, text)

    def test_only_one_release_is_current(self):
        self.publish("1.0.0")
        self.publish("1.0.1")
        current = list(Release.objects.filter(is_current=True)
                       .values_list("version", flat=True))
        self.assertEqual(current, ["1.0.1"])

    def test_not_current_flag(self):
        self.publish("1.0.0")
        self.publish("1.0.1", not_current=True)
        self.assertTrue(Release.objects.get(version="1.0.0").is_current)
        self.assertFalse(Release.objects.get(version="1.0.1").is_current)

    def test_latest_redirects_to_current_release(self):
        self.publish("2.0.0")
        response = self.client.get(reverse("downloads:download_latest"))
        self.assertRedirects(
            response, reverse("downloads:download", args=["2.0.0"]),
            fetch_redirect_response=False)

    def test_duplicate_version_needs_force(self):
        self.publish("3.0.0")
        with self.assertRaises(CommandError):
            call_command("build_release", "3.0.0", stdout=StringIO())
        call_command("build_release", "3.0.0", force=True, stdout=StringIO())
        self.assertEqual(Release.objects.filter(version="3.0.0").count(), 1)

    def test_invalid_version_is_rejected(self):
        for bad in ("../evil", "1.0", "v1.0.0", "1.0.0/../x"):
            with self.subTest(version=bad):
                with self.assertRaises(CommandError):
                    call_command("build_release", bad, stdout=StringIO())

    def test_missing_package_file_is_404(self):
        release = self.publish()
        release.package.storage.delete(release.package.name)
        response = self.client.get(
            reverse("downloads:download", args=[release.version]))
        self.assertEqual(response.status_code, 404)

    def test_build_package_returns_a_zip(self):
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(build_package("1.2.3"))))


class SignatureTests(TestCase):
    def test_signatures_txt_lists_active_only(self):
        Signature.objects.create(sha256="b" * 64, name="Active one")
        Signature.objects.create(sha256="c" * 64, name="Switched off",
                                 active=False)
        text = self.client.get(reverse("downloads:signatures")).content.decode()
        self.assertIn("b" * 64, text)
        self.assertNotIn("c" * 64, text)
        self.assertIn(EICAR_SHA256, text)

    def test_hash_is_lowercased_and_validated(self):
        sig = Signature(sha256="D" * 64, name="Upper")
        sig.full_clean()
        sig.save()
        self.assertEqual(sig.sha256, "d" * 64)
        with self.assertRaises(ValidationError):
            Signature(sha256="not-a-hash", name="Bad").full_clean()

    def test_signature_names_cannot_inject_lines(self):
        Signature.objects.create(sha256="e" * 64, name="Bad\n" + "f" * 64)
        text = self.client.get(reverse("downloads:signatures")).content.decode()
        self.assertEqual(sum(1 for line in text.splitlines()
                             if line.startswith("f" * 64)), 0)


class ScanTests(TestCase):
    url = None

    def setUp(self):
        self.url = reverse("downloads:scan")

    def post(self, *files):
        return self.client.post(self.url, {"files": list(files)})

    def test_eicar_is_flagged_malicious(self):
        response = self.post(upload("test.txt", EICAR))
        self.assertContains(response, "MALICIOUS")
        self.assertContains(response, "test.txt")

    def test_clean_file(self):
        response = self.post(upload("notes.txt", b"just some notes\n"))
        self.assertContains(response, "CLEAN")
        self.assertNotContains(response, "MALICIOUS")

    def test_disguised_executable_is_suspicious(self):
        response = self.post(upload("holiday.jpg", b"MZ\x90\x00" + b"\x00" * 200))
        self.assertContains(response, "SUSPICIOUS")
        self.assertContains(response, "disguised")

    def test_double_extension_is_suspicious(self):
        response = self.post(upload("invoice.pdf.exe", b"hello"))
        self.assertContains(response, "SUSPICIOUS")

    def test_zip_contents_are_scanned(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("docs/eicar.txt", EICAR)
        response = self.post(upload("bundle.zip", buffer.getvalue()))
        self.assertContains(response, "MALICIOUS")
        self.assertContains(response, "inside archive")

    def test_database_signature_is_used(self):
        data = b"a file the database knows about"
        Signature.objects.create(sha256=hashlib.sha256(data).hexdigest(),
                                 name="Known sample")
        response = self.post(upload("thing.bin", data))
        self.assertContains(response, "MALICIOUS")
        self.assertContains(response, "Known sample")

    def test_inactive_database_signature_is_ignored(self):
        data = b"another file"
        Signature.objects.create(sha256=hashlib.sha256(data).hexdigest(),
                                 name="Retired", active=False)
        response = self.post(upload("thing.bin", data))
        self.assertContains(response, "CLEAN")

    def test_no_files_shows_an_error(self):
        response = self.client.post(self.url, {})
        self.assertContains(response, "at least one file")

    @override_settings(SCAN_MAX_FILES=2)
    def test_too_many_files(self):
        response = self.post(*[upload(f"f{i}.txt", b"x") for i in range(3)])
        self.assertContains(response, "at most 2 files")

    @override_settings(SCAN_MAX_FILE_BYTES=100)
    def test_file_too_large(self):
        response = self.post(upload("big.txt", b"x" * 101))
        self.assertContains(response, "larger than")

    def test_path_in_filename_is_stripped(self):
        response = self.post(upload("..\\..\\evil.txt", b"hi"))
        self.assertNotContains(response, "..\\")

    def test_html_in_filename_is_escaped(self):
        response = self.post(upload("<img src=x onerror=alert(1)>.txt", b"hi"))
        self.assertNotContains(response, "<img src=x")
        self.assertContains(response, "&lt;img src=x")

    def test_scan_does_not_store_anything(self):
        before = Release.objects.count(), Signature.objects.count()
        self.post(upload("test.txt", EICAR))
        self.assertEqual((Release.objects.count(), Signature.objects.count()),
                         before)

    def test_scan_responses_are_not_cached(self):
        response = self.client.get(self.url)
        self.assertIn("no-cache", response["Cache-Control"])
