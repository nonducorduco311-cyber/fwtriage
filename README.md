# fwtriage

Stdlib-only firmware triage toolkit. Phase-one triage that turns an unknown
firmware image into a short list of binaries worth opening in Ghidra/IDA. No
pip install required — runs on any Python 3.8+.

## Where it sits in the workflow

```
  fwtriage  (phase 1: breadth, automated)        Ghidra/IDA (phase 2: depth, manual)
  ----------------------------------------       ----------------------------------
  extract & carve the filesystem                 load ONE binary
  ID architecture / endianness / stripped   -->  trace untrusted input -> sink
  flag network-facing services                   find the bug / the leverage
  hunt hardcoded secrets
  => "open the httpd first"
```

fwtriage is the filter that stops you disassembling the wrong binary. It does
not replace Ghidra — it tells you what to point Ghidra at.

## Stages

- `entropy`  — the decider. Flat high entropy => encrypted/compressed blob.
- `extract`  — signature scan; carves via binwalk when present on PATH.
- `classify` — parses every ELF: arch, endianness, bitness, type, stripped.
- `services` — flags network-facing daemons (httpd, telnetd, dropbear, ...).
- `secrets`  — private keys, hardcoded creds, tokens, creds-in-URLs.
- `report`   — assembles the above into a readable (or `--json`) report.

## Usage

```bash
python3 -m fwtriage entropy   firmware.bin
python3 -m fwtriage extract   firmware.bin --out ./out
python3 -m fwtriage classify  ./out/extractions
python3 -m fwtriage services  ./out/extractions
python3 -m fwtriage secrets   ./out/extractions
python3 -m fwtriage all       firmware.bin --out ./out        # full pipeline
python3 -m fwtriage all       ./extracted_rootfs --json       # skip extraction
```

`all` on an image runs entropy + extraction, then classifies and scans the
extracted filesystem. `all` on a directory skips extraction.

## Run it isolated

This tool exists to chew on untrusted firmware. Run it in a disposable,
network-isolated VM and snapshot a clean baseline first; roll back after each
sample. Prefer a non-root user — hostile images include decompression bombs.

## Notes

- binwalk v3 extracts into `extractions/` (not the old `_<file>.extracted/`).
  The extractor resolves either layout.
- `secrets` scans binaries via a strings pass, so expect some false positives
  from regex hits inside compiled code — triage signal, not ground truth.

## Making it yours

`classify.py` is the recommended starting point: the ELF header layout is
small enough to read end to end. Good first changes: extend the `MACHINES`
map, harden the stripped heuristic, or add a section/segment dump.
