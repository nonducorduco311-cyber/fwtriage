"""Extraction stage — find embedded objects and carve the filesystem.

Pure-stdlib signature scanning locates known containers (squashfs, gzip,
cramfs, jffs2, uImage, xz/lzma). Actual carving is delegated to binwalk when
it is present on PATH, since reimplementing every decompressor is out of scope.

Note: binwalk v3 extracts into 'extractions/' (not the old
'_<file>.extracted/' layout). This module resolves either.
"""
import os
import shutil
import subprocess

# magic -> human label
SIGNATURES = {
    b"hsqs": "squashfs (little-endian)",
    b"sqsh": "squashfs (big-endian)",
    b"\x1f\x8b\x08": "gzip stream",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\xfd7zXZ\x00": "xz",
    b"\x5d\x00\x00": "lzma (alone)",
    b"\x45\x3d\xcd\x28": "cramfs (le)",
    b"\x28\xcd\x3d\x45": "cramfs (be)",
    b"\x85\x19": "jffs2 node",
    b"\x27\x05\x19\x56": "uImage (U-Boot)",
    b"UBI#": "UBI",
    b"\x31\x18\x10\x06": "UBIFS",
    b"\x7fELF": "ELF executable",
    b"\xd0\x0d\xfe\xed": "DTB (device tree)",
}


def scan_signatures(path: str, max_hits: int = 200) -> list:
    """Return [{offset, magic, label}] for known magics found in the file."""
    with open(path, "rb") as fh:
        data = fh.read()
    hits = []
    for magic, label in SIGNATURES.items():
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            hits.append({"offset": idx, "magic": magic.hex(), "label": label})
            start = idx + 1
            if len(hits) >= max_hits:
                break
    hits.sort(key=lambda h: h["offset"])
    return hits


def _resolve_extract_dir(image: str, cwd: str) -> str | None:
    base = os.path.basename(image)
    candidates = [
        os.path.join(cwd, "extractions"),                 # binwalk v3
        os.path.join(cwd, f"_{base}.extracted"),          # binwalk v2
        os.path.join(cwd, "extractions", base),
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return None


def extract(image: str, outdir: str) -> dict:
    """Carve with binwalk if available; always return the signature map."""
    sigs = scan_signatures(image)
    result = {"image": image, "signatures": sigs, "extracted_to": None,
              "method": None, "note": None}

    if shutil.which("binwalk"):
        os.makedirs(outdir, exist_ok=True)
        try:
            subprocess.run(
                ["binwalk", "-e", "--directory", outdir, image],
                check=False, capture_output=True, text=True, timeout=600,
            )
            result["method"] = "binwalk"
            result["extracted_to"] = _resolve_extract_dir(image, outdir)
            if not result["extracted_to"]:
                result["note"] = ("binwalk ran but no extraction dir found - "
                                  "image may be an encrypted/opaque blob")
        except subprocess.TimeoutExpired:
            result["note"] = "binwalk timed out (possible decompression bomb)"
    else:
        result["method"] = "signatures-only"
        result["note"] = ("binwalk not on PATH - install it to carve; "
                          "signature offsets above show what is present")
    return result
