"""Service-identification stage — find the network-facing attack surface.

Walks init scripts and config and flags the daemons that listen to the outside
world, because those are the binaries phase-two RE should open first.
"""
import os
import re

# daemon name -> why it matters
NET_DAEMONS = {
    "httpd": "web admin interface", "uhttpd": "web admin (OpenWrt)",
    "lighttpd": "web server", "nginx": "web server", "boa": "embedded web server",
    "mini_httpd": "embedded web server", "goahead": "embedded web server",
    "telnetd": "telnet (often unauthenticated)", "utelnetd": "telnet",
    "dropbear": "SSH server", "sshd": "SSH server",
    "ftpd": "FTP server", "vsftpd": "FTP server", "tftpd": "TFTP server",
    "miniupnpd": "UPnP (network-exposed)", "upnpd": "UPnP",
    "dnsmasq": "DNS/DHCP", "snmpd": "SNMP", "samba": "SMB", "smbd": "SMB",
    "pppd": "PPP", "hostapd": "wifi auth", "wscd": "WPS",
}

INIT_HINTS = ("etc/init.d", "etc/rc", "etc/inittab", "etc/rc.local",
              "etc/config", "etc/services", "etc/xinetd.d")

LISTEN_RX = re.compile(rb"(?i)\b(?:bind|listen|LISTEN|0\.0\.0\.0:\d+|:::\d+)\b")
PORT_RX = re.compile(rb"(?:0\.0\.0\.0|\*):(\d{1,5})")


def identify(root: str) -> dict:
    found = {}          # daemon -> [paths]
    init_files = []
    listen_hits = []

    for dirpath, _dirs, files in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        is_init = any(h in rel_dir.replace("\\", "/") for h in INIT_HINTS)
        for name in files:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                # a symlink named after a daemon still signals presence
                base = name.lower()
                for d in NET_DAEMONS:
                    if base == d:
                        found.setdefault(d, []).append(rel + " (symlink)")
                continue

            base = name.lower()
            if base in NET_DAEMONS:
                found.setdefault(base, []).append(rel)

            if is_init:
                init_files.append(rel)
                try:
                    with open(p, "rb") as fh:
                        data = fh.read(256 * 1024)
                except (OSError, PermissionError):
                    continue
                for d in NET_DAEMONS:
                    if d.encode() in data:
                        found.setdefault(d, []).append(f"{rel} (referenced)")
                for m in PORT_RX.finditer(data):
                    listen_hits.append({"path": rel, "port": m.group(1).decode()})

    surface = [{"daemon": d, "role": NET_DAEMONS[d],
                "locations": sorted(set(locs))} for d, locs in sorted(found.items())]
    return {"root": root, "network_facing": surface,
            "init_files": sorted(set(init_files)),
            "listen_ports": listen_hits}
