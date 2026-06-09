"""Secret-hunting stage — find hardcoded credentials and keys.

Scans text-ish files and pulls printable strings out of binaries, then matches
against patterns for the things that most often turn a firmware image into a
foothold: private keys, hardcoded passwords, API tokens, and creds embedded in
URLs.
"""
import os
import re

PATTERNS = [
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("authorized_keys", re.compile(rb"ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/]{40,}")),
    ("password_assign", re.compile(rb"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{4,}")),
    ("url_with_creds", re.compile(rb"[a-z]+://[^/\s:@]+:[^/\s:@]+@")),
    ("shadow_hash", re.compile(rb"\$[1256][a-z]?\$[./A-Za-z0-9]{8,}\$[./A-Za-z0-9]{16,}")),
    ("private_ip_telnet", re.compile(rb"(?i)telnet(?:d)?[^\n]{0,40}")),
]

SKIP_DIRS = {"proc", "sys", "dev"}
MAX_FILE = 32 * 1024 * 1024  # 32 MB cap per file


def _strings(data: bytes, minlen: int = 5):
    """Yield printable runs (ascii) of length >= minlen from binary data."""
    run = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            run.append(byte)
        else:
            if len(run) >= minlen:
                yield bytes(run)
            run = bytearray()
    if len(run) >= minlen:
        yield bytes(run)


def scan_file(path: str) -> list:
    findings = []
    try:
        if os.path.getsize(path) > MAX_FILE:
            return findings
        with open(path, "rb") as fh:
            data = fh.read()
    except (OSError, PermissionError):
        return findings

    # Match against the raw bytes (covers both text files and binaries).
    for label, rx in PATTERNS:
        for m in rx.finditer(data):
            snippet = m.group(0)[:80].decode("latin-1", "replace")
            findings.append({"type": label, "match": snippet,
                             "offset": m.start()})
    return findings


def scan_dir(root: str, max_findings: int = 500) -> dict:
    results = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                continue
            for f in scan_file(p):
                f["path"] = os.path.relpath(p, root)
                results.append(f)
                if len(results) >= max_findings:
                    return {"root": root, "count": len(results),
                            "findings": results, "truncated": True}
    return {"root": root, "count": len(results),
            "findings": results, "truncated": False}
