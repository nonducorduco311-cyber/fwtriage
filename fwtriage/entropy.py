"""Entropy analysis — the firmware triage decider.

High, flat entropy across a whole image means it is encrypted or compressed
as a single blob: signature carving will find nothing and the next move is to
hunt the decryption routine or go physical (UART/JTAG). Mixed entropy with
structure means the image is extractable.
"""
import math


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def windowed(path: str, window: int = 4096):
    """Yield (offset, entropy) per window across the file."""
    with open(path, "rb") as fh:
        offset = 0
        while True:
            chunk = fh.read(window)
            if not chunk:
                break
            yield offset, shannon_entropy(chunk)
            offset += len(chunk)


def analyze(path: str, window: int = 4096) -> dict:
    """Whole-file verdict plus window statistics."""
    points = list(windowed(path, window))
    if not points:
        return {"path": path, "verdict": "empty", "bits_per_byte": 0.0}
    vals = [e for _, e in points]
    overall = sum(vals) / len(vals)
    lo, hi = min(vals), max(vals)
    spread = hi - lo
    norm = overall / 8.0

    # Flat + very high => blob; wide spread => structured/extractable.
    if norm >= 0.95 and spread < 0.5:
        verdict = "likely ENCRYPTED/COMPRESSED blob - carving will fail; "\
                  "pivot to decryption routine or physical extraction"
    elif spread >= 1.5:
        verdict = "MIXED entropy - structured image, expect extractable regions"
    else:
        verdict = "moderate/uniform - inspect signatures before deciding"

    return {
        "path": path,
        "bits_per_byte": round(overall, 3),
        "normalized": round(norm, 3),
        "window_min": round(lo, 3),
        "window_max": round(hi, 3),
        "spread": round(spread, 3),
        "windows": len(vals),
        "verdict": verdict,
    }
