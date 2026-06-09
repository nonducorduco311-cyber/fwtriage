"""Reporting stage — assemble stage outputs into a readable triage report."""
import json


def _h(title):
    line = "=" * 64
    return f"\n{line}\n  {title}\n{line}"


def render_text(data: dict) -> str:
    out = []
    out.append(_h("FWTRIAGE REPORT"))
    out.append(f"  target: {data.get('target')}")

    ent = data.get("entropy")
    if ent:
        out.append(_h("ENTROPY (the decider)"))
        out.append(f"  bits/byte : {ent['bits_per_byte']}  (normalized {ent['normalized']})")
        out.append(f"  spread    : {ent['spread']}  over {ent['windows']} windows")
        out.append(f"  verdict   : {ent['verdict']}")

    ext = data.get("extraction")
    if ext:
        out.append(_h("EXTRACTION"))
        out.append(f"  method      : {ext['method']}")
        out.append(f"  extracted_to: {ext['extracted_to']}")
        if ext.get("note"):
            out.append(f"  note        : {ext['note']}")
        if ext.get("signatures"):
            out.append("  signatures:")
            for s in ext["signatures"][:25]:
                out.append(f"    0x{s['offset']:08x}  {s['label']}")

    cls = data.get("classification")
    if cls:
        out.append(_h("CLASSIFICATION"))
        out.append(f"  ELF binaries: {cls['elf_count']}")
        for k, v in sorted(cls["by_arch"].items(), key=lambda x: -x[1]):
            out.append(f"    {v:>5}  {k}")

    svc = data.get("services")
    if svc:
        out.append(_h("NETWORK-FACING SURFACE (open these first)"))
        if not svc["network_facing"]:
            out.append("  none identified")
        for s in svc["network_facing"]:
            out.append(f"  * {s['daemon']:<12} - {s['role']}")
            for loc in s["locations"][:4]:
                out.append(f"      {loc}")
        if svc.get("listen_ports"):
            out.append("  listen ports referenced:")
            for lp in svc["listen_ports"][:15]:
                out.append(f"    :{lp['port']:<6} {lp['path']}")

    sec = data.get("secrets")
    if sec:
        out.append(_h("SECRETS"))
        out.append(f"  findings: {sec['count']}" + (" (truncated)" if sec.get("truncated") else ""))
        for f in sec["findings"][:40]:
            out.append(f"  [{f['type']}] {f['path']} @0x{f['offset']:x}")
            out.append(f"      {f['match']}")

    out.append("")
    return "\n".join(out)


def render(data: dict, as_json: bool = False) -> str:
    if as_json:
        return json.dumps(data, indent=2, default=str)
    return render_text(data)
