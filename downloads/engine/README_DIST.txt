ShieldScan
==========

A small offline file scanner. Not a replacement for Microsoft Defender,
Malwarebytes or another full antivirus. Use it as a second opinion.

Needs Python 3.8 or newer. Nothing else to install. No network access.

Files in this folder
  shieldscan.py   the scanner (read it, it is short)
  signatures.txt  SHA-256 hashes of known-bad files, one per line
  rules.txt       optional custom script rules

Quick start
  python shieldscan.py scan "C:\Users\YourName\Downloads"        (Windows)
  python3 shieldscan.py scan ~/Downloads                          (macOS, Linux)

Useful options
  --quarantine           move malicious files to ~/.shieldscan/quarantine
  --include-suspicious   with --quarantine, move suspicious files too
  --html report.html     write a report you can open in a browser
  --report report.json   write a machine-readable report
  --exclude NAME ...     skip folders with these names

Other commands
  python shieldscan.py watch ~/Downloads --quarantine    check new files every 5s
  python shieldscan.py list-quarantine
  python shieldscan.py restore ID

Nothing is ever deleted. Quarantined files can be restored.

Test it first
  Save the harmless EICAR test string in a file and scan it. Every antivirus
  program is expected to flag it. Your browser or Defender may block you from
  saving that file, which is a good sign about them, not a problem with this.

What a clean result means
  None of the checks fired. It does not prove a file is safe.
