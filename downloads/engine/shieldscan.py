#!/usr/bin/env python3
"""
ShieldScan 1.1 - a small, open-source, offline file scanner.

What it does
  * Hashes every file (SHA-256) and compares against a local signature list
    (signatures.txt, one hash per line, optional "  # name" comment).
  * Detects the standard EICAR antivirus test file.
  * Looks inside ZIP archives (one level deep) and scans the files in them.
  * Applies heuristics: disguised executables (e.g. an .exe named .jpg),
    double extensions (invoice.pdf.exe), packed or encrypted executables
    (very high entropy), and scripts with patterns commonly used to hide or
    download code.
  * Accepts your own script rules in rules.txt.
  * Can move flagged files to a quarantine folder (never deletes anything),
    restore them, and watch a folder for new files.
  * Writes JSON and HTML reports.

What it does not do
  * It has no kernel-level real-time protection, no cloud lookups and no
    automatic updates. "watch" checks a folder every few seconds.
  * It is not a replacement for Microsoft Defender, Malwarebytes, or similar.
    Use it as a second opinion and as a learning tool.

Requires Python 3.8+ and nothing else. No network access is used.

Usage
  python shieldscan.py scan PATH [--quarantine] [--include-suspicious]
                                 [--report report.json] [--html report.html]
                                 [--rules rules.txt] [--exclude NAME ...]
  python shieldscan.py watch PATH [--interval 5] [--quarantine]
  python shieldscan.py list-quarantine
  python shieldscan.py restore ID
"""

import argparse
import hashlib
import html
import io
import json
import math
import os
import re
import shutil
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

VERSION = "1.1.0"

HOME = Path.home() / ".shieldscan"
QUARANTINE_DIR = HOME / "quarantine"
MANIFEST = QUARANTINE_DIR / "manifest.json"
SCRIPT_DIR = Path(__file__).resolve().parent
SIGNATURE_FILE = SCRIPT_DIR / "signatures.txt"
RULES_FILE = SCRIPT_DIR / "rules.txt"

# The EICAR test string is a harmless, industry-standard file that every
# antivirus program is expected to flag. Built from two halves so this
# source file is not itself mistaken for the test file.
EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
    "ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

MAX_READ = 50 * 1024 * 1024      # skip content checks on files larger than 50 MB
ZIP_MAX_ENTRIES = 500            # look at no more than this many files per archive
ZIP_MAX_RATIO = 200              # skip entries that expand more than 200x (zip bombs)
ENTROPY_LIMIT = 7.4              # bits per byte; above this an executable looks packed

EXEC_MAGIC = {
    b"MZ": "Windows executable",
    b"\x7fELF": "Linux executable",
    b"\xfe\xed\xfa\xce": "macOS executable",
    b"\xfe\xed\xfa\xcf": "macOS executable",
    b"\xcf\xfa\xed\xfe": "macOS executable",
    b"\xca\xfe\xba\xbe": "macOS/Java executable",
}

SAFE_LOOKING_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".txt", ".mp3", ".mp4", ".zip", ".rtf",
}
RUNNABLE_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jse", ".wsf", ".ps1", ".msi", ".jar", ".lnk", ".hta",
}
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf",
              ".hta", ".sh", ".py"}

# (regex, description, score)
SCRIPT_PATTERNS = [
    (re.compile(rb"powershell[^\n]{0,40}-e(nc|ncodedcommand)\b", re.I),
     "PowerShell encoded command", 3),
    (re.compile(rb"-windowstyle\s+hidden", re.I),
     "Hidden PowerShell window", 2),
    (re.compile(rb"downloadstring|downloadfile|invoke-webrequest|iwr\s",
                re.I),
     "Downloads content from the internet", 2),
    (re.compile(rb"frombase64string|base64\s+-d|atob\(", re.I),
     "Decodes base64 data", 1),
    (re.compile(rb"invoke-expression|\biex\b|eval\(|exec\(", re.I),
     "Runs dynamically built code", 1),
    (re.compile(rb"wscript\.shell|createobject\(\s*[\"']wscript", re.I),
     "Launches programs from a script", 2),
    (re.compile(rb"schtasks\s+/create|reg\s+add\s+hk[a-z_]+\\[^\n]*\\run",
                re.I),
     "Sets itself to run at startup", 3),
    (re.compile(rb"vssadmin\s+delete\s+shadows", re.I),
     "Deletes Windows backup copies", 5),
    (re.compile(rb"curl[^\n|]{0,200}\|\s*(ba)?sh|wget[^\n|]{0,200}\|\s*(ba)?sh",
                re.I),
     "Pipes a download straight into a shell", 3),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".shieldscan"}


# --------------------------------------------------------------------------
# Loading signatures and rules
# --------------------------------------------------------------------------

def load_signatures(path=SIGNATURE_FILE):
    sigs = {}
    if not path.exists():
        return sigs
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition("#")
        digest = digest.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", digest):
            sigs[digest] = name.strip() or "Known bad file"
    return sigs


def load_rules(path=None):
    """Read custom script rules. One per line:  score | description | regex"""
    path = Path(path) if path else RULES_FILE
    rules = []
    if not path.exists():
        return rules
    for n, line in enumerate(
            path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|", 2)]
        if len(parts) != 3 or not parts[0].isdigit():
            print(f"rules: skipped line {n} (expected: score | text | regex)",
                  file=sys.stderr)
            continue
        try:
            rules.append((re.compile(parts[2].encode(), re.I),
                          parts[1], int(parts[0])))
        except re.error as e:
            print(f"rules: skipped line {n} ({e})", file=sys.stderr)
    return rules


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    """Shannon entropy in bits per byte (0 to 8)."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total)
                for c in Counter(data).values())


def analyse_data(name, data, signatures, rules):
    """Analyse file contents already in memory. Returns (score, reasons)."""
    digest = hashlib.sha256(data).hexdigest()
    if digest in signatures:
        return 10, ["Matches signature: " + signatures[digest]]
    if not data:
        return 0, []
    if EICAR in data[:200]:
        return 10, ["EICAR antivirus test file"]

    reasons = []
    score = 0
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    name_parts = os.path.basename(lower).split(".")

    kind = next((label for magic, label in EXEC_MAGIC.items()
                 if data.startswith(magic)), None)

    # Executable disguised as a document or picture.
    if kind and ext in SAFE_LOOKING_EXT:
        score += 4
        reasons.append(f"{kind} disguised as a {ext} file")

    # Executable that looks packed or encrypted.
    if kind and len(data) >= 4096:
        e = entropy(data[:1024 * 1024])
        if e >= ENTROPY_LIMIT:
            score += 2
            reasons.append(f"Executable looks packed or encrypted "
                           f"(entropy {e:.2f} of 8)")

    # invoice.pdf.exe style names.
    if (len(name_parts) >= 3 and ("." + name_parts[-1]) in RUNNABLE_EXT
            and ("." + name_parts[-2]) in SAFE_LOOKING_EXT):
        score += 3
        reasons.append("Double extension (looks like a document, runs as a program)")

    # Script content.
    if ext in SCRIPT_EXT:
        script_score = 0
        script_reasons = []
        for pattern, label, pts in SCRIPT_PATTERNS + rules:
            if pattern.search(data):
                script_score += pts
                script_reasons.append(label)
        # One weak signal is common in legitimate scripts, so only report
        # scripts whose combined signals reach the threshold.
        if script_score >= 3:
            score += script_score
            reasons.extend(script_reasons)

    return score, reasons


def analyse_zip(path, signatures, rules):
    """Scan the files inside a ZIP archive, one level deep."""
    score = 0
    reasons = []
    try:
        with zipfile.ZipFile(path) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if len(infos) > ZIP_MAX_ENTRIES:
                reasons.append(f"Archive has {len(infos)} files; "
                               f"only the first {ZIP_MAX_ENTRIES} were checked")
                infos = infos[:ZIP_MAX_ENTRIES]
            for info in infos:
                if info.flag_bits & 0x1:
                    continue  # password-protected entry cannot be read
                if info.file_size > MAX_READ:
                    continue
                if (info.compress_size and info.file_size > 10 * 1024 * 1024
                        and info.file_size / info.compress_size > ZIP_MAX_RATIO):
                    reasons.append(f"{info.filename}: expands more than "
                                   f"{ZIP_MAX_RATIO}x (possible zip bomb), not opened")
                    score = max(score, 3)
                    continue
                try:
                    data = z.read(info)
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    continue
                s, r = analyse_data(info.filename, data, signatures, rules)
                if s >= 3:
                    score = max(score, s)
                    reasons.extend(f"inside archive, {info.filename}: {x}"
                                   for x in r)
            if any(i.flag_bits & 0x1 for i in infos):
                reasons.append("Archive has password-protected files that "
                               "could not be checked")
                score = max(score, 1)
    except (zipfile.BadZipFile, OSError):
        pass
    return score, reasons


def analyse(path, signatures, rules):
    """Return (score, [reasons], sha256) for one file on disk."""
    try:
        size = path.stat().st_size
        digest = sha256_of(path)
    except (OSError, PermissionError):
        return 0, [], None

    if digest in signatures:
        return 10, ["Matches signature: " + signatures[digest]], digest
    if size == 0 or size > MAX_READ:
        return 0, [], digest

    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
    except (OSError, PermissionError):
        return 0, [], digest

    score, reasons = analyse_data(path.name, data, signatures, rules)

    if data[:4] == b"PK\x03\x04" and zipfile.is_zipfile(io.BytesIO(data)):
        zs, zr = analyse_zip(path, signatures, rules)
        score = max(score, zs)
        reasons.extend(zr)

    return score, reasons, digest


def verdict(score):
    if score >= 8:
        return "MALICIOUS"
    if score >= 3:
        return "SUSPICIOUS"
    return "CLEAN"


def walk(root, exclude=()):
    root = Path(root)
    if root.is_file():
        yield root
        return
    skip = SKIP_DIRS | set(exclude)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                yield p


# --------------------------------------------------------------------------
# Quarantine
# --------------------------------------------------------------------------

def load_manifest():
    try:
        return json.loads(MANIFEST.read_text())
    except (OSError, ValueError):
        return {}


def save_manifest(m):
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(m, indent=2))


def quarantine(path, reasons, digest):
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    qid = digest[:12] + "-" + str(int(time.time()))
    dest = QUARANTINE_DIR / (qid + ".quarantined")
    shutil.move(str(path), str(dest))
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    manifest[qid] = {
        "original_path": str(path),
        "sha256": digest,
        "reasons": reasons,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_manifest(manifest)
    return qid


def handle_file(path, signatures, rules, args):
    """Scan one file, optionally quarantine it. Returns a finding or None."""
    score, reasons, digest = analyse(path, signatures, rules)
    v = verdict(score)
    if v == "CLEAN":
        return None
    entry = {"path": str(path), "verdict": v, "score": score,
             "reasons": reasons, "sha256": digest}
    if args.quarantine:
        if v == "SUSPICIOUS" and not args.include_suspicious:
            entry["action"] = "left in place (use --include-suspicious)"
        else:
            try:
                entry["quarantine_id"] = quarantine(path, reasons, digest)
                entry["action"] = "quarantined"
            except OSError as e:
                entry["action"] = f"could not quarantine: {e}"
    print(f"[{v}] {path}")
    for r in reasons:
        print(f"    - {r}")
    if "action" in entry:
        print(f"    > {entry['action']}")
    return entry


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def write_html_report(path, target, scanned, seconds, findings):
    rows = []
    for f in findings:
        cls = f["verdict"].lower()
        why = "".join(f"<li>{html.escape(r)}</li>" for r in f["reasons"])
        act = html.escape(f.get("action", ""))
        rows.append(
            f"<tr><td><span class='p {cls}'>{f['verdict']}</span></td>"
            f"<td class='m'>{html.escape(f['path'])}"
            f"<br><small>{html.escape(f['sha256'] or '')}</small></td>"
            f"<td><ul>{why}</ul></td><td>{act}</td></tr>")
    body = "".join(rows) or "<tr><td colspan='4'>No files were flagged.</td></tr>"
    page = f"""<!doctype html><meta charset="utf-8">
<title>ShieldScan report</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:70rem;padding:0 1rem;color:#14202b}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:.5rem .7rem;border-bottom:1px solid #cfd7de;vertical-align:top}}
th{{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:#55646f}}
.m{{font-family:ui-monospace,Consolas,monospace;font-size:.85rem;overflow-wrap:anywhere}}
small{{color:#55646f}}ul{{margin:0;padding-left:1.1rem}}
.p{{font:600 .72rem ui-monospace,monospace;padding:.15rem .5rem;border-radius:99px}}
.malicious{{background:#fbe9df;color:#b8420d}}.suspicious{{background:#f8efd2;color:#8a6100}}
</style>
<h1>ShieldScan report</h1>
<p>Target: <b>{html.escape(str(target))}</b><br>
{scanned} files checked in {seconds:.1f}s. {len(findings)} flagged.
Version {VERSION}, {time.strftime('%Y-%m-%d %H:%M:%S')}.</p>
<table><thead><tr><th>Verdict</th><th>File</th><th>Why</th><th>Action</th></tr></thead>
<tbody>{body}</tbody></table>"""
    Path(path).write_text(page, encoding="utf-8")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_scan(args):
    signatures = load_signatures()
    rules = load_rules(args.rules)
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2

    print(f"ShieldScan {VERSION}  |  {len(signatures)} signatures, "
          f"{len(rules)} custom rules")
    print(f"Scanning {target} ...\n")

    scanned = 0
    findings = []
    start = time.time()
    for path in walk(target, args.exclude):
        scanned += 1
        entry = handle_file(path, signatures, rules, args)
        if entry:
            findings.append(entry)
        if scanned % 500 == 0:
            print(f"  ... {scanned} files checked", file=sys.stderr)

    elapsed = time.time() - start
    print(f"\nDone. {scanned} files checked in {elapsed:.1f}s, "
          f"{len(findings)} flagged.")
    if args.report:
        Path(args.report).write_text(json.dumps({
            "version": VERSION, "target": str(target), "scanned": scanned,
            "seconds": round(elapsed, 2), "findings": findings}, indent=2))
        print(f"JSON report written to {args.report}")
    if args.html:
        write_html_report(args.html, target, scanned, elapsed, findings)
        print(f"HTML report written to {args.html}")
    return 1 if any(f["verdict"] == "MALICIOUS" for f in findings) else 0


def cmd_watch(args):
    signatures = load_signatures()
    rules = load_rules(args.rules)
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2

    def stamp(p):
        try:
            st = p.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    print(f"ShieldScan {VERSION} watching {target} every {args.interval}s. "
          f"Press Ctrl+C to stop.")
    # Files already present are recorded but not scanned; run "scan" for those.
    seen = {p: stamp(p) for p in walk(target, args.exclude)}
    cycles = 0
    try:
        while args.cycles is None or cycles < args.cycles:
            time.sleep(args.interval)
            cycles += 1
            for p in walk(target, args.exclude):
                s = stamp(p)
                if s is None or seen.get(p) == s:
                    continue
                seen[p] = s
                time.sleep(0.3)  # let a download finish writing
                handle_file(p, signatures, rules, args)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_list(_args):
    m = load_manifest()
    if not m:
        print("Quarantine is empty.")
        return 0
    for qid, info in m.items():
        print(f"{qid}  {info['time']}  {info['original_path']}")
        for r in info["reasons"]:
            print(f"    - {r}")
    return 0


def cmd_restore(args):
    m = load_manifest()
    info = m.get(args.id)
    if not info:
        print("No such quarantine ID. Run list-quarantine.", file=sys.stderr)
        return 2
    src = QUARANTINE_DIR / (args.id + ".quarantined")
    dest = Path(info["original_path"])
    if dest.exists():
        dest = dest.with_name(dest.name + ".restored")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    del m[args.id]
    save_manifest(m)
    print(f"Restored to {dest}")
    return 0


def main():
    p = argparse.ArgumentParser(
        prog="shieldscan",
        description="Small offline file scanner. Not a replacement for a "
                    "full antivirus.")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--quarantine", action="store_true",
                        help="move malicious files to quarantine")
        sp.add_argument("--include-suspicious", action="store_true",
                        help="with --quarantine, also move suspicious files")
        sp.add_argument("--rules", help="custom rules file (default: rules.txt "
                                        "next to this script)")
        sp.add_argument("--exclude", nargs="*", default=[], metavar="DIR",
                        help="folder names to skip")

    s = sub.add_parser("scan", help="scan a file or folder")
    s.add_argument("path")
    common(s)
    s.add_argument("--report", help="write a JSON report to this file")
    s.add_argument("--html", help="write an HTML report to this file")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="scan new and changed files in a folder")
    w.add_argument("path")
    common(w)
    w.add_argument("--interval", type=float, default=5.0,
                   help="seconds between checks (default 5)")
    w.add_argument("--cycles", type=int, default=None, help=argparse.SUPPRESS)
    w.set_defaults(func=cmd_watch)

    l = sub.add_parser("list-quarantine", help="show quarantined files")
    l.set_defaults(func=cmd_list)

    r = sub.add_parser("restore", help="restore a quarantined file")
    r.add_argument("id")
    r.set_defaults(func=cmd_restore)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
