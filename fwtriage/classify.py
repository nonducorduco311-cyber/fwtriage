"""Classification stage — find and characterize ELF binaries.

For every ELF on the filesystem this answers the questions that gate phase-two
RE: architecture, endianness, bitness, type, and whether it is stripped. The
goal is to turn a filesystem of hundreds of binaries into a short list worth
opening in Ghidra.

This module is the recommended starting point for making the toolkit your own:
the ELF header layout below is small enough to read end to end, and extending
the e_machine map or the stripped heuristic is a clean first modification.
"""
import os
import struct

ELF_MAGIC = b"\x7fELF"

# e_machine -> architecture name
MACHINES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
    0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0x2A: "SuperH",
    0xF3: "RISC-V", 0x02: "SPARC", 0x32: "IA-64", 0x16: "S390",
}
ETYPES = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}


def parse_elf(path: str) -> dict | None:
    """Parse the ELF header. Returns None if the file is not an ELF."""
    with open(path, "rb") as fh:
        head = fh.read(64)
        if len(head) < 20 or head[:4] != ELF_MAGIC:
            return None

        ei_class = head[4]            # 1 = 32-bit, 2 = 64-bit
        ei_data = head[5]             # 1 = little-endian, 2 = big-endian
        endian = "<" if ei_data == 1 else ">"
        bits = 32 if ei_class == 1 else 64

        e_type = struct.unpack(endian + "H", head[16:18])[0]
        e_machine = struct.unpack(endian + "H", head[18:20])[0]

        info = {
            "path": path,
            "arch": MACHINES.get(e_machine, f"unknown(0x{e_machine:02x})"),
            "endian": "little" if ei_data == 1 else "big",
            "bits": bits,
            "type": ETYPES.get(e_type, f"type({e_type})"),
            "stripped": _is_stripped(fh, head, endian, bits),
        }
        return info


def _is_stripped(fh, head, endian, bits) -> bool | None:
    """Best-effort: a binary is 'stripped' if it has no .symtab section.

    Walks the section-header string table looking for a symbol table. Returns
    None if section headers are absent (also effectively stripped to the OS).
    """
    try:
        if bits == 32:
            e_shoff = struct.unpack(endian + "I", head[32:36])[0]
            e_shentsize = struct.unpack(endian + "H", head[46:48])[0]
            e_shnum = struct.unpack(endian + "H", head[48:50])[0]
            e_shstrndx = struct.unpack(endian + "H", head[50:52])[0]
            name_off = 0  # sh_name at offset 0 of section header
        else:
            e_shoff = struct.unpack(endian + "Q", head[40:48])[0]
            e_shentsize = struct.unpack(endian + "H", head[58:60])[0]
            e_shnum = struct.unpack(endian + "H", head[60:62])[0]
            e_shstrndx = struct.unpack(endian + "H", head[62:64])[0]
            name_off = 0

        if e_shoff == 0 or e_shnum == 0:
            return None  # no section headers at all

        # Read section headers
        fh.seek(e_shoff)
        sh_raw = fh.read(e_shentsize * e_shnum)
        # Locate the section-header string table
        shstr = sh_raw[e_shstrndx * e_shentsize: (e_shstrndx + 1) * e_shentsize]
        if bits == 32:
            str_off = struct.unpack(endian + "I", shstr[16:20])[0]
            str_size = struct.unpack(endian + "I", shstr[20:24])[0]
        else:
            str_off = struct.unpack(endian + "Q", shstr[24:32])[0]
            str_size = struct.unpack(endian + "Q", shstr[32:40])[0]
        fh.seek(str_off)
        strtab = fh.read(str_size)
        return b".symtab" not in strtab
    except Exception:
        return None


def classify_dir(root: str) -> dict:
    """Walk a directory, characterize every ELF, and summarize."""
    binaries = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                info = parse_elf(p)
                if info:
                    info["path"] = os.path.relpath(p, root)
                    binaries.append(info)
            except (OSError, PermissionError):
                continue

    summary = {}
    for b in binaries:
        key = f"{b['arch']}/{b['endian']}/{b['bits']}-bit"
        summary[key] = summary.get(key, 0) + 1

    return {"root": root, "elf_count": len(binaries),
            "by_arch": summary, "binaries": binaries}
