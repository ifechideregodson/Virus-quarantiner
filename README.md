# ShieldScan website

A Django project that publishes **ShieldScan**, a small offline antivirus scanner, and lets visitors download it, verify the download, and check files in the browser.

## What is in it

| Page | What it does |
| --- | --- |
| `/` | Landing page with the current release, its SHA-256 and a download button |
| `/releases/` | Every release with notes, size, download count and checksum |
| `/download/latest/`, `/download/<version>/` | Counted downloads of the release ZIP |
| `/scan/` | Upload up to 10 files (10 MB each) and see the verdicts. Files are read in memory and never saved |
| `/docs/` | Commands, scoring table and honest limits |
| `/signatures.txt` | The live signature list, built from the database |
| `/admin/` | Publish releases, add or switch off signatures |

The scanner itself is `downloads/engine/shieldscan.py`. The same file is imported by the `/scan/` page and packed into every release ZIP, so what people download is what the site runs.

## Run it locally

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export DJANGO_DEBUG=1                # Windows PowerShell: $env:DJANGO_DEBUG = "1"
python manage.py migrate
python manage.py createsuperuser
python manage.py build_release       # packages and publishes the current scanner
python manage.py runserver
```

Open http://127.0.0.1:8000/.

## Run the tests first

```bash
python manage.py test
```

The suite covers the pages, release packaging and checksums, download counting, the signature list, and the upload scanner (EICAR, disguised files, ZIPs, limits, escaping).

## Publishing a release

```bash
python manage.py build_release 1.2.0 --notes "Adds RAR detection"
python manage.py build_release 1.2.0 --force            # replace an existing version
python manage.py build_release 1.3.0-rc1 --not-current  # publish without making it current
```

The command builds `shieldscan-<version>.zip` containing `shieldscan.py`, `rules.txt`, `README.txt` and a fresh `signatures.txt` made from the active signatures in the database, then records its SHA-256 and size. Only one release is marked current at a time.

To ship scanner changes: edit `downloads/engine/shieldscan.py`, raise `VERSION` inside it, then run `build_release`.

You can also upload a ZIP by hand in the admin under Releases. The checksum and size are filled in automatically.

## Managing signatures

In the admin under Signatures, add the SHA-256 of a file you know is malicious. Switch signatures off instead of deleting them. New releases pick up the active list, and `/signatures.txt` always shows the current one. The `/scan/` page uses the database list immediately.

## Deploying

```bash
export DJANGO_SECRET_KEY="..."                     # required when DJANGO_DEBUG is off
export DJANGO_ALLOWED_HOSTS="example.com"
export DJANGO_CSRF_TRUSTED_ORIGINS="https://example.com"
export DJANGO_HTTPS=1                              # secure cookies, HSTS, HTTPS redirect

python manage.py migrate
python manage.py collectstatic --noinput
gunicorn config.wsgi --bind 0.0.0.0:8000
```

Static files are served by WhiteNoise. Release ZIPs live in `MEDIA_ROOT` (`DJANGO_MEDIA_ROOT`) and are served only through the download view. Back up that folder and the SQLite file (`DJANGO_DB_PATH`), or point `DATABASES` at PostgreSQL. See `.env.example`.

## Notes on safety

- The upload page reads each file into memory, scans it and drops it. Nothing is written to disk and no scan history is kept.
- Limits are `SCAN_MAX_FILES` and `SCAN_MAX_FILE_BYTES` in `config/settings.py`. Put your reverse proxy's request-size limit and rate limiting in front of `/scan/` on a public site.
- ZIP entries that expand more than 200 times (over 10 MB) are not opened.
- ShieldScan is a second opinion, not a replacement for Microsoft Defender or another full antivirus. The site says so on every page.

## Layout

```
manage.py
config/                  settings, urls, wsgi, asgi
templates/base.html      shared layout
downloads/
  models.py              Release, Signature
  views.py, urls.py      pages, downloads, upload scan
  services.py            signature list, upload scanning, release packaging
  forms.py               multi-file upload form
  admin.py               release and signature admin
  engine/                shieldscan.py, rules.txt, README_DIST.txt
  management/commands/build_release.py
  static/downloads/site.css
  tests.py
```
