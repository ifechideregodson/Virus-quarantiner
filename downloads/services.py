"""Glue between the website and the ShieldScan engine."""
import hashlib
import io
import os
import zipfile
from functools import lru_cache
from pathlib import Path

from django.utils import timezone

from .engine import shieldscan
from .models import Signature

ENGINE_DIR = Path(shieldscan.__file__).resolve().parent
EICAR_SHA256 = hashlib.sha256(shieldscan.EICAR).hexdigest()


def active_signature_map():
    """{sha256: name} for every active signature, plus the EICAR test file."""
    signatures = {s.sha256: s.name
                  for s in Signature.objects.filter(active=True)}
    signatures.setdefault(EICAR_SHA256, "EICAR test file")
    return signatures


def _one_line(text):
    return " ".join(str(text).split()).replace("#", "")


def render_signatures_txt():
    """The signatures.txt that ships in releases and at /signatures.txt."""
    lines = [
        '# ShieldScan signature list. One SHA-256 per line, optional "# name".',
        f"# Generated {timezone.now():%Y-%m-%d %H:%M} UTC",
    ]
    items = sorted(active_signature_map().items(), key=lambda kv: kv[1].lower())
    for digest, name in items:
        lines.append(f"{digest}  # {_one_line(name)}")
    return "\n".join(lines) + "\n"


@lru_cache(maxsize=1)
def engine_rules():
    """Custom script rules that ship with the engine (rules.txt)."""
    return tuple(shieldscan.load_rules(ENGINE_DIR / "rules.txt"))


def scan_bytes(filename, data, signatures, rules=()):
    """Scan one uploaded file held in memory. Nothing is written to disk."""
    name = os.path.basename(str(filename).replace("\\", "/")) or "unnamed"
    rules = list(rules)
    score, reasons = shieldscan.analyse_data(name, data, signatures, rules)
    if data[:4] == b"PK\x03\x04" and zipfile.is_zipfile(io.BytesIO(data)):
        zip_score, zip_reasons = shieldscan.analyse_zip(
            io.BytesIO(data), signatures, rules)
        score = max(score, zip_score)
        reasons.extend(zip_reasons)
    return {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "score": score,
        "verdict": shieldscan.verdict(score),
        "reasons": reasons,
    }


def build_package(version):
    """Return the bytes of a release ZIP for the given version."""
    root = f"shieldscan-{version}/"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(ENGINE_DIR / "shieldscan.py", root + "shieldscan.py")
        archive.write(ENGINE_DIR / "rules.txt", root + "rules.txt")
        archive.write(ENGINE_DIR / "README_DIST.txt", root + "README.txt")
        archive.writestr(root + "signatures.txt", render_signatures_txt())
    return buffer.getvalue()
