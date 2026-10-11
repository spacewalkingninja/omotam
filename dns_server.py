#!/usr/bin/env python3
"""
Custom DNS server for a local network.

- Returns custom answers for domains listed in dns_hosts.json
- Forwards every other query to an upstream resolver
- Supports A, AAAA and CNAME overrides (plus wildcards and blocking)
- Speaks both UDP and TCP on the configured port

Run as Administrator so it can bind port 53.
    python dns_server.py
    python dns_server.py --config dns_hosts.json --port 53
    python dns_server.py --test example.com   # query the running server
"""

import argparse
import collections
import datetime
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}
QTYPE_BY_NAME = {v: k for k, v in QTYPES.items()}

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4


LOG_BUFFER = collections.deque(maxlen=300)
LOG_LOCK = threading.Lock()
LOG_TOTAL = 0

QUERY_LOG = collections.deque(maxlen=50000)
QUERY_LOCK = threading.Lock()

VERSION = "1.0.2"
REPO = "spacewalkingninja/omotam"
UPDATE_CACHE = {"ts": 0.0, "result": None}
UPDATE_LOCK = threading.Lock()


def _parse_version(value):
    parts = []
    for chunk in str(value).lstrip("vV").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def check_updates(timeout=8):
    import urllib.request
    url = "https://api.github.com/repos/{}/releases/latest".format(REPO)
    req = urllib.request.Request(url, headers={
        "User-Agent": "omotam/{}".format(VERSION),
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "current": VERSION,
                "latest": VERSION, "update_available": False}
    latest = (data.get("tag_name") or data.get("name") or "").lstrip("vV")
    asset = next((a.get("browser_download_url") for a in data.get("assets", [])
                  if str(a.get("name", "")).endswith(".zip")), None)
    result = {
        "ok": True,
        "current": VERSION,
        "latest": latest or VERSION,
        "update_available": _parse_version(latest) > _parse_version(VERSION),
        "release_url": data.get("html_url"),
        "download_url": asset,
        "notes": (data.get("body") or "")[:1500],
        "published_at": data.get("published_at"),
    }
    with UPDATE_LOCK:
        UPDATE_CACHE["ts"] = time.time()
        UPDATE_CACHE["result"] = result
    return result


def get_update_status(max_age=3600, force=False):
    with UPDATE_LOCK:
        ts = UPDATE_CACHE["ts"]
        result = UPDATE_CACHE["result"]
    if force or result is None or (time.time() - ts) > max_age:
        return check_updates()
    return result


def update_checker_loop(config):
    hours = float(config.get("update_check_hours", 6) or 6)
    while True:
        try:
            res = check_updates()
            if res.get("ok") and res.get("update_available"):
                log("UPDATE AVAILABLE: {} (current {}) -> {}".format(
                    res["latest"], VERSION, res.get("release_url")))
            elif res.get("ok"):
                log("update check: up to date (v{})".format(VERSION))
            else:
                log("update check failed: {}".format(res.get("error")))
        except Exception as exc:  # noqa: BLE001
            log("update check error: {}".format(exc))
        time.sleep(max(1800, int(hours * 3600)))


def run_updater():
    base = os.path.dirname(os.path.abspath(STATE.path))
    script = os.path.join(base, "update.ps1")
    if not os.path.exists(script):
        return False, "update.ps1 not found in {}".format(base)
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
            creationflags=0x00000008)  # DETACHED_PROCESS
        return True, script
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def log(msg):
    global LOG_TOTAL
    line = "[{}] {}".format(time.strftime("%H:%M:%S"), msg)
    with LOG_LOCK:
        LOG_BUFFER.append(line)
        LOG_TOTAL += 1
    print(line, flush=True)


def parse_name(data, offset):
    """Parse a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    jumped = False
    next_offset = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 128:
                raise ValueError("compression loop")
            continue
        if (length & 0xC0) != 0:
            raise ValueError("bad label length")
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), next_offset


def encode_name(name):
    if name in ("", "."):
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", "ignore")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def build_response(query, question, answers, rcode=RCODE_NOERROR, aa=True):
    tid, flags = struct.unpack("!HH", query[:4])
    resp_flags = 0x8000  # QR
    resp_flags |= 0x0100 & flags  # copy RD
    resp_flags |= 0x0080  # RA
    if aa:
        resp_flags |= 0x0400
    resp_flags = (resp_flags & ~0x000F) | (rcode & 0x0F)

    qdcount = 1
    header = struct.pack("!HHHHHH", tid, resp_flags, qdcount, len(answers), 0, 0)
    return header + question + b"".join(answers)


def make_answer(qname_ptr, rtype, rdata, ttl):
    return (qname_ptr + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata)


def encode_txt(text):
    raw = text.encode("utf-8", "replace")
    if not raw:
        return b"\x00"
    out = bytearray()
    for i in range(0, len(raw), 255):
        chunk = raw[i:i + 255]
        out.append(len(chunk))
        out += chunk
    return bytes(out)


def skip_name(data, offset):
    """Return the offset just past a (possibly compressed) name."""
    hops = 0
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
        hops += 1
        if hops > 128 or offset > len(data):
            raise ValueError("bad name in packet")


def detect_lan_ip(exclude=None):
    """Best-effort LAN IPv4. Ignores loopback and any excluded (e.g. loopback-hijacked) IPs."""
    exclude = set(exclude or [])

    def is_private(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    candidates = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in exclude:
                candidates.append(ip)
    except OSError:
        pass
    for ip in candidates:
        if is_private(ip):
            return ip
    if candidates:
        return candidates[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.168.0.1", 80))
        ip = sock.getsockname()[0]
        return ip if not ip.startswith("127.") else "127.0.0.1"
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def resolve_paths(config, config_path):
    base = os.path.dirname(os.path.abspath(config_path))

    def rp(p):
        return p if os.path.isabs(p) else os.path.join(base, p)

    hostnames = config.get("gui_hostname", "dns.settings")
    if isinstance(hostnames, str):
        hostnames = [hostnames]
    hostnames = [h.strip() for h in hostnames if h and h.strip()]
    return {
        "hostnames": hostnames,
        "cert": rp(config.get("gui_cert", "dns.settings.crt")),
        "key": rp(config.get("gui_key", "dns.settings.key")),
        "ca": rp(config.get("gui_ca", "dns.settings-ca.crt")),
        "ca_key": rp(config.get("gui_ca_key", "dns.settings-ca.key")),
        "crl": rp(config.get("gui_crl", "dns.settings")),
    }


def _http_bases(config, paths):
    """http:// base URLs (no auth) clients can use to fetch CRL/OCSP."""
    port = int(config.get("gui_port", 8080))
    candidates = []
    if paths["hostnames"]:
        candidates.append(paths["hostnames"][0])
    candidates.append("127.0.0.1")
    ip = detect_lan_ip(config.get("intercept_ips"))
    if ip and ip != "127.0.0.1":
        candidates.append(ip)
    out, seen = [], set()
    for host in candidates:
        base = "http://{}:{}".format(host, port)
        if base not in seen:
            seen.add(base)
            out.append(base)
    return out


def revocation_urls(config, paths):
    bases = _http_bases(config, paths)
    crl_urls = []
    if config.get("gui_crl_url"):
        crl_urls = [str(config["gui_crl_url"])]
    elif config.get("revocation_crl", True):
        crl_urls = [b + "/crl" for b in bases]
    ocsp_url = None
    if config.get("gui_ocsp_url"):
        ocsp_url = str(config["gui_ocsp_url"])
    elif config.get("revocation_ocsp", False):
        ocsp_url = bases[0] + "/ocsp"
    return crl_urls, ocsp_url


def _load_ca_key(ca_key_path):
    from cryptography.hazmat.primitives import serialization
    if not os.path.exists(ca_key_path):
        return None
    try:
        with open(ca_key_path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    except Exception:  # noqa: BLE001
        return None


def _trust_ca(ca_path):
    """Best-effort: add the local CA to this machine's Trusted Root store."""
    if os.name != "nt":
        return
    try:
        safe = ca_path.replace("'", "''")
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\LocalMachine\\Root' | Out-Null".format(safe)],
            capture_output=True, timeout=30)
        if proc.returncode == 0:
            log("trusted local CA: {}".format(ca_path))
        else:
            log("could not trust CA automatically; run as Administrator or import {} manually".format(ca_path))
    except Exception as exc:  # noqa: BLE001
        log("could not trust CA automatically (import it manually): {}".format(exc))


def generate_certificates(cert_path, key_path, ca_path, hostnames, ca_key_path=None,
                          crl_urls=None, ocsp_url=None):
    """Issue a leaf cert (chained to a local CA) for the hostnames.

    Reuses an existing CA key/cert when present so trust is preserved.
    Optionally advertises a CRL distribution point and/or an OCSP responder.
    Returns True when a brand-new CA was created."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID

    if ca_key_path is None:
        ca_key_path = ca_path + ".key"

    pem = serialization.Encoding.PEM
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = _load_ca_key(ca_key_path) if os.path.exists(ca_path) else None
    new_ca = ca_key is None
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Omotam Local CA")])

    if new_ca:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(ca_key_path, "wb") as fh:
            fh.write(ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        with open(ca_path, "wb") as fh:
            fh.write(ca_cert.public_bytes(pem))
    else:
        with open(ca_path, "rb") as fh:
            ca_cert = x509.load_pem_x509_certificate(fh.read())
        ca_name = ca_cert.subject

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    san_names = [x509.DNSName(h) for h in hostnames]
    for extra in ("localhost",):
        if extra not in hostnames:
            san_names.append(x509.DNSName(extra))
    ip = detect_lan_ip()
    san_ips = [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    if ip != "127.0.0.1":
        san_ips.append(x509.IPAddress(ipaddress.ip_address(ip)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name).issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_names + san_ips), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    if crl_urls:
        points = [x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(u)],
                                         relative_name=None, reasons=None, crl_issuer=None)
                  for u in crl_urls]
        builder = builder.add_extension(x509.CRLDistributionPoints(points), critical=False)
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                       x509.UniformResourceIdentifier(ocsp_url))
            ]), critical=False)

    leaf_cert = builder.sign(ca_key, hashes.SHA256())
    with open(cert_path, "wb") as fh:
        fh.write(leaf_cert.public_bytes(pem))
        fh.write(ca_cert.public_bytes(pem))
    with open(key_path, "wb") as fh:
        fh.write(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return new_ca


def generate_crl(paths, config):
    """Write a fresh (empty) CRL signed by the local CA, as .der and .pem."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    if not (os.path.exists(paths["ca"]) and os.path.exists(paths["ca_key"])):
        return None
    ca_key = _load_ca_key(paths["ca_key"])
    if ca_key is None:
        return None
    with open(paths["ca"], "rb") as fh:
        ca_cert = x509.load_pem_x509_certificate(fh.read())
    now = datetime.datetime.now(datetime.timezone.utc)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(days=1))
        .next_update(now + datetime.timedelta(days=1825))
        .sign(ca_key, hashes.SHA256())
    )
    with open(paths["crl"] + ".der", "wb") as fh:
        fh.write(crl.public_bytes(serialization.Encoding.DER))
    with open(paths["crl"] + ".pem", "wb") as fh:
        fh.write(crl.public_bytes(serialization.Encoding.PEM))
    return paths["crl"] + ".der"


def build_ocsp_response(request_der, paths):
    """Answer an OCSP request: GOOD for our leaf, UNKNOWN otherwise."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import ocsp
    try:
        req = ocsp.load_der_ocsp_request(request_der)
    except Exception:  # noqa: BLE001
        return None
    ca_key = _load_ca_key(paths["ca_key"])
    if ca_key is None or not os.path.exists(paths["ca"]):
        return None
    try:
        with open(paths["ca"], "rb") as fh:
            ca_cert = x509.load_pem_x509_certificate(fh.read())
        with open(paths["cert"], "rb") as fh:
            leaf = x509.load_pem_x509_certificate(fh.read())
        now = datetime.datetime.now(datetime.timezone.utc)
        status = ocsp.OCSPCertStatus.GOOD if req.serial_number == leaf.serial_number \
            else ocsp.OCSPCertStatus.UNKNOWN
        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=leaf, issuer=ca_cert, algorithm=req.hash_algorithm, cert_status=status,
            this_update=now, next_update=now + datetime.timedelta(days=7),
            revocation_time=None, revocation_reason=None)
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
        return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    except Exception as exc:  # noqa: BLE001
        log("OCSP response error: {}".format(exc))
        try:
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.INTERNAL_ERROR).public_bytes(serialization.Encoding.DER)
        except Exception:  # noqa: BLE001
            return None


def _cert_covers(cert_path, hostnames, ips, want_crl=False, want_ocsp=False):
    from cryptography import x509
    try:
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have_dns = set(san.get_values_for_type(x509.DNSName))
        have_ip = {str(x) for x in san.get_values_for_type(x509.IPAddress)}
        want_dns = set(hostnames) | {"localhost"}
        if not (want_dns.issubset(have_dns) and set(ips).issubset(have_ip)):
            return False
        has_crl = any(e.oid == x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS for e in cert.extensions)
        has_ocsp = any(e.oid == x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS for e in cert.extensions)
        return has_crl == bool(want_crl) and has_ocsp == bool(want_ocsp)
    except Exception:  # noqa: BLE001
        return False


def ensure_certificates(paths, config=None):
    """Ensure a leaf cert covering the configured hostnames + LAN IP, plus the
    configured revocation extensions, exists. Re-issues (reusing the CA) otherwise."""
    config = config or {}
    want_ips = ["127.0.0.1"]
    ip = detect_lan_ip(config.get("intercept_ips"))
    if ip != "127.0.0.1":
        want_ips.append(ip)
    crl_urls, ocsp_url = revocation_urls(config, paths)
    if (os.path.exists(paths["cert"]) and os.path.exists(paths["key"]) and os.path.exists(paths["ca"])
            and _cert_covers(paths["cert"], paths["hostnames"], want_ips,
                             want_crl=bool(crl_urls), want_ocsp=bool(ocsp_url))):
        return False
    new_ca = generate_certificates(paths["cert"], paths["key"], paths["ca"], paths["hostnames"],
                                   paths.get("ca_key"), crl_urls=crl_urls, ocsp_url=ocsp_url)
    if new_ca:
        _trust_ca(paths["ca"])
    return True


def make_ssl_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


# Hostnames used to bootstrap DNS-over-HTTPS. Returning NXDOMAIN for these
# stops browsers from resolving over DoH, forcing them back to system DNS.
# "use-application-dns.net" is Firefox's official canary for exactly this.
DOH_HOSTS = [
    "use-application-dns.net",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "one.one.one.one",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.nextdns.io",
    "doh.dnsforge.net",
    "dns.adguard.com",
    "doh.adguard.com",
    "doh.dns.sb",
]

DEFAULT_INTERCEPT_IPS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]


def _run_powershell(command, timeout=45):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except FileNotFoundError:
        return 1, "powershell not found"
    except Exception as exc:
        return 1, str(exc)


def apply_interception(ips, enable, manage_dns=True):
    """Add/remove resolver IPs on the loopback adapter so local queries to them
    hit this server. Optionally point this PC's DNS at 127.0.0.1."""
    ip_list = ",".join("'%s'" % ip for ip in ips)
    if enable:
        body = (
            "$idx=(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '127.0.0.1').InterfaceIndex;"
            "foreach($ip in @(%s)){"
            "  if(-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue)){"
            "    New-NetIPAddress -InterfaceIndex $idx -IPAddress $ip -PrefixLength 32 -ErrorAction SilentlyContinue | Out-Null;"
            "    Write-Output ('+ ' + $ip) } }" % ip_list
        )
        if manage_dns:
            body += (
                "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {"
                "  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1','::1' -ErrorAction SilentlyContinue }"
            )
    else:
        body = (
            "foreach($ip in @(%s)){"
            "  Remove-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -Confirm:$false -ErrorAction SilentlyContinue;"
            "  Write-Output ('- ' + $ip) }" % ip_list
        )
        if manage_dns:
            body += (
                "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {"
                "  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue }"
            )
    return _run_powershell(body)


def sync_interception(config, verbose=True):
    ips = config.get("intercept_ips") or DEFAULT_INTERCEPT_IPS
    enable = bool(config.get("intercept_enabled", False))
    rc, out = apply_interception(ips, enable, manage_dns=enable)
    if verbose:
        state = "enabled" if enable else "disabled"
        if rc == 0:
            log("override mode {}: {}".format(state, out.replace("\n", " ") or "ok"))
        else:
            log("override mode {} failed (run as Administrator): {}".format(state, out))


def _probe_dns(server, port=53, timeout=1.5):
    """Return True if the given resolver answers a test query."""
    packet = struct.pack("!HHHHHH", 0x0D0D, 0x0100, 1, 0, 0, 0) + \
        encode_name("example.com") + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        sock.recvfrom(4096)
        return True
    except OSError:
        return False
    finally:
        sock.close()


class Resolver:
    def __init__(self, config):
        self.reload(config)

    def reload(self, config):
        self.upstream = config.get("upstream", "1.1.1.1")
        self.upstream_port = int(config.get("upstream_port", 53))
        self.ttl = int(config.get("ttl", 60))
        self.default_action = config.get("default_action", "forward")
        self.intercept_enabled = bool(config.get("intercept_enabled", False))
        self.intercept_ips = [str(x).strip() for x in (config.get("intercept_ips") or DEFAULT_INTERCEPT_IPS) if str(x).strip()]
        self.record_queries = bool(config.get("record_queries", False))
        self.block_doh = config.get("block_doh")
        if self.block_doh is None:
            self.block_doh = self.intercept_enabled

        self.upstream_overridden = False
        if self.intercept_enabled and self.upstream in self.intercept_ips:
            candidates = [
                str(config.get("intercept_upstream", "")).strip(),
                "9.9.9.10", "208.67.222.222", "208.67.220.220",
                "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "64.6.64.6",
            ]
            candidates = [c for c in candidates if c and c not in self.intercept_ips]
            chosen = next((c for c in candidates if _probe_dns(c, self.upstream_port)), None)
            if chosen:
                self.upstream = chosen
                self.upstream_overridden = True

        records = {}
        for name, value in config.get("records", {}).items():
            records[name.lower().rstrip(".")] = self._normalize(value)

        if self.block_doh:
            for host in DOH_HOSTS:
                records.setdefault(host, self._normalize("BLOCK"))

        self.records = records

    @staticmethod
    def _normalize(value):
        rec = {"A": [], "AAAA": [], "CNAME": None, "TXT": [],
               "rcode": RCODE_NOERROR, "block": False, "merge": False}
        if isinstance(value, str):
            if value.strip().upper() in ("BLOCK", "NXDOMAIN"):
                rec["block"] = True
                rec["rcode"] = RCODE_NXDOMAIN
                return rec
            value = {"A": [value]}
        if isinstance(value, list):
            value = {"A": value}
        for key, val in value.items():
            ku = key.upper()
            if ku in ("MERGE", "PASSTHROUGH"):
                rec["merge"] = bool(val) if not isinstance(val, list) else True
                continue
            if ku in ("BLOCK", "NXDOMAIN"):
                rec["block"] = bool(val) if not isinstance(val, list) else True
                rec["rcode"] = RCODE_NXDOMAIN
                continue
            vals = val if isinstance(val, list) else [val]
            if ku == "A":
                rec["A"] = [str(v) for v in vals]
            elif ku == "AAAA":
                rec["AAAA"] = [str(v) for v in vals]
            elif ku == "CNAME":
                rec["CNAME"] = str(vals[0]).rstrip(".")
            elif ku == "TXT":
                rec["TXT"] = [str(v) for v in vals]
            else:
                raise ValueError("unknown record type: {}".format(key))
        if any(str(v).upper() == "BLOCK" for v in rec["A"]):
            rec["block"] = True
            rec["rcode"] = RCODE_NXDOMAIN
            rec["A"] = []
        return rec

    def build_custom_answers(self, rec, qtype, qname_ptr):
        answers = []
        if rec["CNAME"]:
            answers.append(make_answer(qname_ptr, 5, encode_name(rec["CNAME"]), self.ttl))
            return answers
        if qtype in (1, 255):
            for ip in rec["A"]:
                try:
                    answers.append(make_answer(qname_ptr, 1, socket.inet_aton(ip), self.ttl))
                except OSError:
                    log("invalid A record: {}".format(ip))
        if qtype in (28, 255):
            for ip in rec["AAAA"]:
                try:
                    answers.append(make_answer(qname_ptr, 28, socket.inet_pton(socket.AF_INET6, ip), self.ttl))
                except OSError:
                    log("invalid AAAA record: {}".format(ip))
        if qtype in (16, 255):
            for text in rec["TXT"]:
                answers.append(make_answer(qname_ptr, 16, encode_txt(text), self.ttl))
        return answers

    def merge_response(self, upstream, extra):
        """Append custom answer records right after the upstream answer section."""
        if not extra:
            return upstream
        try:
            tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", upstream[:12])
            off = 12
            for _ in range(qd):
                off = skip_name(upstream, off) + 4
            for _ in range(an):
                off = skip_name(upstream, off)
                rdlen = struct.unpack("!H", upstream[off + 8:off + 10])[0]
                off += 10 + rdlen
            new_flags = flags & 0xFFF0  # force rcode = NOERROR
            header = struct.pack("!HHHHHH", tid, new_flags, qd, an + len(extra), ns, ar)
            return header + upstream[12:off] + b"".join(extra) + upstream[off:]
        except (struct.error, ValueError, IndexError):
            log("could not merge upstream response; returning custom answer only")
            return None

    def lookup(self, name):
        name = name.lower().rstrip(".")
        if name in self.records:
            return self.records[name]
        parts = name.split(".")
        for i in range(1, len(parts)):
            wildcard = "*." + ".".join(parts[i:])
            if wildcard in self.records:
                return self.records[wildcard]
        return None

    def resolve(self, data, addr):
        if len(data) < 12:
            return None
        _, _, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
        if qdcount < 1:
            return build_response(data, b"", [], RCODE_FORMERR, aa=False)
        try:
            name, off = parse_name(data, 12)
        except ValueError as exc:
            log("malformed query from {}: {}".format(addr[0], exc))
            return build_response(data, b"", [], RCODE_FORMERR, aa=False)
        if off + 4 > len(data):
            return build_response(data, b"", [], RCODE_FORMERR, aa=False)
        qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
        question = data[12:off + 4]

        rec = self.lookup(name)
        if rec is None:
            resp = self.forward(data, addr)
            if resp is not None:
                an = struct.unpack("!HHHHHH", resp[:12])[3]
                self._log_query(addr, name, qtype, "forward", "{} answer(s)".format(an))
            else:
                self._log_query(addr, name, qtype, "forward", "no upstream response")
            return resp
        if rec["block"]:
            log("BLOCK  {} ({}) from {}".format(name, QTYPES.get(qtype, qtype), addr[0]))
            self._log_query(addr, name, qtype, "block", "NXDOMAIN")
            return build_response(data, question, [], rec["rcode"])

        qname_ptr = b"\xc0\x0c"
        custom = self.build_custom_answers(rec, qtype, qname_ptr)

        if rec["merge"]:
            upstream = self.forward(data, addr)
            if upstream is None:
                self._log_query(addr, name, qtype, "custom", self._detail(rec, custom))
                return build_response(data, question, custom)
            if custom:
                log("MERGE  {} ({}) +{} custom from {}".format(
                    name, QTYPES.get(qtype, qtype), len(custom), addr[0]))
                merged = self.merge_response(upstream, custom)
                self._log_query(addr, name, qtype, "merge", self._detail(rec, custom))
                if merged is not None:
                    return merged
                return build_response(data, question, custom)
            an = struct.unpack("!HHHHHH", upstream[:12])[3]
            self._log_query(addr, name, qtype, "forward", "{} answer(s)".format(an))
            return upstream

        if custom:
            labels = rec["A"] + rec["AAAA"] + rec["TXT"]
            target = ", ".join(labels) if labels else rec["CNAME"]
            log("CUSTOM {} -> {} from {}".format(name, target, addr[0]))
            self._log_query(addr, name, qtype, "custom", self._detail(rec, custom))
        else:
            log("NODATA {} ({}) from {}".format(name, QTYPES.get(qtype, qtype), addr[0]))
            self._log_query(addr, name, qtype, "nodata", "")
        return build_response(data, question, custom)

    @staticmethod
    def _detail(rec, custom):
        labels = rec["A"] + rec["AAAA"] + rec["TXT"]
        if labels:
            return ", ".join(labels)
        return rec["CNAME"] or "{} answer(s)".format(len(custom))

    def _log_query(self, addr, name, qtype, action, detail=""):
        if not self.record_queries:
            return
        entry = {
            "ts": time.time(),
            "client": addr[0] if addr else "",
            "name": name,
            "type": QTYPES.get(qtype, str(qtype)),
            "action": action,
            "detail": detail,
        }
        with QUERY_LOCK:
            QUERY_LOG.append(entry)

    def forward(self, data, addr):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4.0)
            sock.sendto(data, (self.upstream, self.upstream_port))
            resp, _ = sock.recvfrom(65535)
            sock.close()
            return resp
        except socket.timeout:
            log("upstream timeout for query from {}".format(addr[0]))
            return None
        except OSError as exc:
            log("upstream error: {}".format(exc))
            return None


class State:
    """Holds the live config + resolver and serialises config writes."""

    def __init__(self, path, config):
        self.path = path
        self.lock = threading.Lock()
        self.config = config
        self.resolver = Resolver(config)

    def reload(self, config):
        with self.lock:
            self.config = config
            self.resolver = Resolver(config)

    def save(self, config):
        with self.lock:
            self._persist(config)

    def _persist(self, config):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
        os.replace(tmp, self.path)
        self.config = config
        self.resolver = Resolver(config)

    def upsert_record(self, name, value):
        with self.lock:
            config = dict(self.config)
            records = dict(config.get("records", {}))
            records[name] = value
            config["records"] = records
            self._persist(config)
            return config

    def delete_record(self, name):
        with self.lock:
            config = dict(self.config)
            records = dict(config.get("records", {}))
            existed = records.pop(name, None) is not None
            config["records"] = records
            self._persist(config)
            return existed

    def patch_settings(self, **settings):
        with self.lock:
            config = dict(self.config)
            config.update(settings)
            self._persist(config)
            return config

    def load_from_disk(self):
        with open(self.path, "r", encoding="utf-8-sig") as fh:
            config = json.load(fh)
        self.reload(config)
        return config


STATE = None


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = STATE.resolver.resolve(data, self.client_address)
        if resp:
            sock.sendto(resp, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def handle(self):
        self.request.settimeout(10)
        while True:
            try:
                head = self.recv_exact(2)
                if not head:
                    break
                length = struct.unpack("!H", head)[0]
                data = self.recv_exact(length)
                if not data:
                    break
                resp = STATE.resolver.resolve(data, self.client_address)
                if not resp:
                    break
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
            except (socket.timeout, OSError):
                break


class ThreadedUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedUDP6(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


class ThreadedTCP6(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


GUI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Omotam</title>
<style>
  :root { --bg:#0f1115; --panel:#171a21; --line:#2a2f3a; --txt:#e6e9ef; --mut:#8b93a3; --acc:#4f8cff; --ok:#37d67a; --bad:#ff5c5c; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:Consolas,Menlo,monospace; background:var(--bg); color:var(--txt); font-size:14px; }
  header { padding:16px 20px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  h1 { font-size:16px; margin:0; letter-spacing:1px; }
  .dot { width:9px; height:9px; border-radius:50%; background:var(--ok); box-shadow:0 0 8px var(--ok); }
  .mut { color:var(--mut); }
  main { padding:20px; max-width:1000px; margin:0 auto; display:grid; gap:18px; }
  section { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }
  h2 { font-size:12px; text-transform:uppercase; letter-spacing:1.5px; color:var(--mut); margin:0 0 12px; }
  label { display:block; font-size:11px; color:var(--mut); margin-bottom:4px; }
  input, select, button { font-family:inherit; font-size:13px; background:#0d0f13; color:var(--txt); border:1px solid var(--line); border-radius:6px; padding:8px 10px; }
  input:focus, select:focus { outline:1px solid var(--acc); }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; }
  .field { flex:1; min-width:120px; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { font-size:11px; color:var(--mut); text-transform:uppercase; letter-spacing:1px; }
  td input, td select { width:100%; }
  td.narrow { width:120px; }
  td.act { width:40px; }
  .del { background:transparent; border:none; color:var(--bad); cursor:pointer; font-size:16px; padding:2px 6px; }
  .btns { display:flex; gap:10px; margin-top:14px; flex-wrap:wrap; }
  button.primary { background:var(--acc); border-color:var(--acc); color:#fff; cursor:pointer; }
  button.primary:hover { filter:brightness(1.1); }
  button.ghost { cursor:pointer; }
  #notes { width:100%; height:220px; resize:vertical; font-size:12px; line-height:1.6; color:#b7c0d0; background:#0d0f13; border:1px solid var(--line); border-radius:6px; padding:10px; white-space:pre-wrap; }
  label.chk { display:flex; align-items:center; gap:6px; cursor:pointer; color:var(--mut); font-size:12px; }
  label.chk input { width:auto; }
  #msg { font-size:12px; min-height:16px; }
  .ok { color:var(--ok); } .bad { color:var(--bad); }
  .badge { font-size:10px; border:1px solid var(--line); border-radius:20px; padding:2px 8px; color:var(--mut); }
</style>
</head>
<body>
<header>
  <span class="dot"></span>
  <h1>Omotam</h1>
  <span class="badge">DNS</span>
  <span class="mut" id="status">loading...</span>
</header>
<main>
  <section id="updatebanner" style="display:none; border-color:var(--acc)">
    <h2>Update available</h2>
    <div class="row" style="align-items:center; gap:12px">
      <span id="updateText" style="flex:1"></span>
      <button class="primary" id="updateNow">Update now</button>
      <button class="ghost" onclick="document.getElementById('updatebanner').style.display='none'">Dismiss</button>
    </div>
    <div class="mut" style="font-size:11px; margin-top:6px">omotam will restart to apply the update.</div>
  </section>

  <section>
    <h2>Server</h2>
    <div class="row">
      <div class="field"><label>Upstream resolver</label><input id="upstream" placeholder="1.1.1.1"></div>
      <div class="field" style="max-width:150px"><label>TTL (seconds)</label><input id="ttl" type="number" min="0"></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div class="field"><label>Answer for these resolver addresses (comma separated)</label><input id="targets" placeholder="1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4"></div>
    </div>
    <label style="margin-top:14px; display:flex; align-items:center; gap:8px; color:var(--txt); font-size:13px">
      <input type="checkbox" id="intercept" style="width:auto">
      Override mode &mdash; hijack 1.1.1.1 / 8.8.8.8 on this PC
    </label>
    <div class="mut" style="font-size:11px; margin-top:6px; line-height:1.5">
      Makes the public resolver IPs local loopback addresses so any query to them hits this server,
      switches the forwarder to avoid a loop, and disables browser DoH. Requires the server to run as Administrator.
    </div>
    <div class="row" style="margin-top:16px; align-items:center; gap:20px">
      <span class="mut" style="font-size:12px">Certificate revocation (HTTPS clients):</span>
      <label class="chk" style="display:flex; align-items:center; gap:6px; color:var(--txt); font-size:13px">
        <input type="checkbox" id="revCrl" style="width:auto"> Serve CRL
      </label>
      <label class="chk" style="display:flex; align-items:center; gap:6px; color:var(--txt); font-size:13px">
        <input type="checkbox" id="revOcsp" style="width:auto"> Serve OCSP
      </label>
      <span class="mut" id="revStatus" style="font-size:11px"></span>
    </div>
    <div class="mut" style="font-size:11px; margin-top:6px; line-height:1.5">
      Toggle these to test how strict clients (e.g. curl) handle revocation. CRL covers Schannel;
      OCSP is a responder at <code>/ocsp</code>. Changing either re-issues the cert and reloads HTTPS.
    </div>
  </section>

  <section>
    <h2>Domain overrides</h2>
    <table>
      <thead><tr><th>Domain</th><th class="narrow">Type</th><th>Value</th><th class="narrow" title="Also return this domain's normal records from upstream">Passthrough</th><th class="act"></th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div class="btns">
      <button class="ghost" onclick="addRow()">+ Add record</button>
      <button class="primary" onclick="save()">Save &amp; apply</button>
      <button class="ghost" onclick="reload()">Reload from disk</button>
      <span id="msg"></span>
    </div>
  </section>

  <section>
    <h2>DNS query recording</h2>
    <div class="row" style="align-items:center; gap:12px">
      <button id="recStart" class="primary" onclick="setRecording(true)">Start Recording</button>
      <button id="recEnd" class="ghost" onclick="setRecording(false)">End Recording</button>
      <span id="recState" class="mut">Recording: off</span>
    </div>
    <div class="mut" style="font-size:11px; margin-top:6px">Recording is off by default. While on, requests are captured so you can view and export them below.</div>
    <div class="row" style="margin-top:12px; align-items:flex-end">
      <div class="field" style="max-width:230px"><label>From</label><input type="datetime-local" id="qfrom"></div>
      <div class="field" style="max-width:230px"><label>To</label><input type="datetime-local" id="qto"></div>
      <button class="ghost" onclick="quickRange(15)">15m</button>
      <button class="ghost" onclick="quickRange(60)">1h</button>
      <button class="ghost" onclick="quickRange(1440)">24h</button>
      <button class="primary" onclick="loadQueries()">View</button>
      <button class="ghost" onclick="exportQueries('csv')">Export CSV</button>
      <button class="ghost" onclick="exportQueries('json')">Export JSON</button>
      <button class="ghost" onclick="clearQueries()">Clear</button>
      <span id="qmsg"></span>
    </div>
    <div class="mut" id="qcount" style="margin-top:10px; font-size:12px"></div>
    <div style="max-height:340px; overflow:auto; margin-top:8px">
      <table>
        <thead><tr><th class="narrow">Time</th><th class="narrow">Client</th><th>Domain</th><th class="narrow">Type</th><th class="narrow">Action</th><th>Detail</th></tr></thead>
        <tbody id="qrows"></tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Activity &amp; notes</h2>
    <textarea id="notes" spellcheck="false" placeholder="Editable and saved to dns_activity.txt. New server activity is appended below while Live is checked."></textarea>
    <div class="btns">
      <button class="primary" onclick="saveNotes()">Save</button>
      <button class="ghost" onclick="loadNotes()">Reload</button>
      <button class="ghost" onclick="clearNotes()">Clear</button>
      <label class="chk"><input type="checkbox" id="live" checked> Live</label>
      <span id="msg2"></span>
    </div>
  </section>
</main>
<script>
const TOKEN = __TOKEN__;
const q = TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "";
const types = ["A", "AAAA", "TXT", "CNAME", "BLOCK"];

function el(tag, attrs, kids) {
  const e = document.createElement(tag);
  for (const k in (attrs||{})) { if (k === "text") e.textContent = attrs[k]; else e.setAttribute(k, attrs[k]); }
  for (const c of (kids||[])) e.appendChild(c);
  return e;
}

function addRow(domain, type, value, merge) {
  const tbody = document.getElementById("rows");
  const tr = document.createElement("tr");
  const d = el("input", { value: domain||"", placeholder:"example.com or *.example.com" });
  const t = el("select");
  for (const ty of types) {
    const o = el("option", { value: ty, text: ty });
    if (ty === (type||"A")) o.selected = true;
    t.appendChild(o);
  }
  const v = el("input", { value: value||"", placeholder:"10.0.0.5 or text value" });
  const m = el("input", { type:"checkbox", title:"keep upstream records for this domain", style:"width:auto" });
  if (merge) m.checked = true;
  const del = el("button", { class:"del", text:"\u00d7", title:"remove" });
  del.onclick = () => tr.remove();
  const tds = [el("td", {}, [d]), el("td", { class:"narrow" }, [t]), el("td", {}, [v]), el("td", { class:"narrow", style:"text-align:center" }, [m]), el("td", { class:"act" }, [del])];
  tds.forEach(x => tr.appendChild(x));
  tbody.appendChild(tr);
}

function toRows(records) {
  const rows = [];
  for (const domain in records) {
    const val = records[domain];
    if (typeof val === "string") {
      rows.push([domain, val.toUpperCase() === "BLOCK" ? "BLOCK" : "A", val.toUpperCase() === "BLOCK" ? "" : val, false]);
    } else if (Array.isArray(val)) {
      val.forEach(v => rows.push([domain, "A", v, false]));
    } else {
      const merge = !!val.merge;
      const A = val.A ? [].concat(val.A) : [];
      const AAAA = val.AAAA ? [].concat(val.AAAA) : [];
      const TXT = val.TXT ? [].concat(val.TXT) : [];
      A.forEach(v => rows.push([domain, "A", v, merge]));
      AAAA.forEach(v => rows.push([domain, "AAAA", v, merge]));
      TXT.forEach(v => rows.push([domain, "TXT", v, merge]));
      if (val.CNAME) rows.push([domain, "CNAME", val.CNAME, merge]);
      if (val.BLOCK || val.NXDOMAIN) rows.push([domain, "BLOCK", "", merge]);
    }
  }
  return rows;
}

function fromRows() {
  const domains = {};
  document.querySelectorAll("#rows tr").forEach(tr => {
    const domain = tr.children[0].firstChild.value.trim().toLowerCase().replace(/\.$/, "");
    if (!domain) return;
    const type = tr.children[1].firstChild.value;
    const value = tr.children[2].firstChild.value.trim();
    const merge = tr.children[3].firstChild.checked;
    const d = domains[domain] || (domains[domain] = { A:[], AAAA:[], TXT:[], CNAME:null, merge:false, block:false });
    if (merge) d.merge = true;
    if (type === "BLOCK") { d.block = true; return; }
    if (type === "CNAME") { d.CNAME = value; return; }
    d[type].push(value);
  });
  const records = {};
  for (const domain in domains) {
    const d = domains[domain];
    if (d.block) { records[domain] = "BLOCK"; continue; }
    const obj = {};
    if (d.A.length) obj.A = d.A;
    if (d.AAAA.length) obj.AAAA = d.AAAA;
    if (d.TXT.length) obj.TXT = d.TXT;
    if (d.CNAME) obj.CNAME = d.CNAME;
    if (d.merge) obj.merge = true;
    records[domain] = obj;
  }
  return records;
}

function setMsg(text, good) {
  const m = document.getElementById("msg");
  m.textContent = text;
  m.className = good ? "ok" : "bad";
}

function load() {
  fetch("/api/config" + q).then(r => r.json()).then(cfg => {
    document.getElementById("upstream").value = cfg.upstream;
    document.getElementById("ttl").value = cfg.ttl;
    document.getElementById("intercept").checked = !!cfg.intercept_enabled;
    document.getElementById("targets").value = (cfg.intercept_ips || []).join(", ");
    document.getElementById("revCrl").checked = cfg.revocation_crl !== false;
    document.getElementById("revOcsp").checked = cfg.revocation_ocsp === true;
    document.getElementById("revStatus").textContent = "CRL " + (cfg.revocation_crl !== false ? "on" : "off") + " \u00b7 OCSP " + (cfg.revocation_ocsp === true ? "on" : "off");
    updateRecState(cfg.record_queries === true);
    const gui = cfg.tls && cfg.tls_port === 443 ? "https://" + cfg.hostname + "/" : "GUI :" + cfg.gui_port;
    document.getElementById("status").textContent = "v" + (cfg.version || "?") + " \u2022 listening :" + cfg.port + " \u2022 " + gui + (cfg.intercept_enabled ? " \u2022 OVERRIDE" : "") + (cfg.token_required ? " \u2022 token" : "");
    const tbody = document.getElementById("rows");
    tbody.innerHTML = "";
    toRows(cfg.records).forEach(r => addRow(r[0], r[1], r[2], r[3]));
  }).catch(e => setMsg("load failed: " + e, false));
}

function save() {
  const payload = {
    upstream: document.getElementById("upstream").value.trim(),
    ttl: parseInt(document.getElementById("ttl").value || "60", 10),
    intercept_enabled: document.getElementById("intercept").checked,
    intercept_ips: document.getElementById("targets").value,
    revocation_crl: document.getElementById("revCrl").checked,
    revocation_ocsp: document.getElementById("revOcsp").checked,
    records: fromRows()
  };
  fetch("/api/config" + q, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(payload) })
    .then(r => r.json()).then(res => {
      if (res.ok) { setMsg("saved at " + new Date().toLocaleTimeString(), true); load(); }
      else setMsg("error: " + res.error, false);
    }).catch(e => setMsg("save failed: " + e, false));
}

function updateRecState(on) {
  const state = document.getElementById("recState");
  if (state) state.textContent = "Recording: " + (on ? "ON" : "off");
  const start = document.getElementById("recStart");
  const end = document.getElementById("recEnd");
  if (start) start.disabled = !!on;
  if (end) end.disabled = !on;
}

function setRecording(on) {
  fetch("/api/settings" + q, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ record_queries: on }) })
    .then(r => r.json()).then(res => {
      if (res.ok) { updateRecState(res.settings.record_queries); if (on) loadQueries(); }
      else setQMsg("error: " + res.error, false);
    }).catch(e => setQMsg("failed: " + e, false));
}

function checkUpdate(force) {
  const path = force ? "/api/update/check" : "/api/update";
  const opts = force ? { method: "POST" } : {};
  fetch(path + q, opts).then(r => r.json()).then(u => {
    if (!u) return;
    if (u.ok && u.update_available) {
      const banner = document.getElementById("updatebanner");
      banner.style.display = "block";
      document.getElementById("updateText").textContent =
        "omotam " + u.latest + " is available (you have " + u.current + ").";
      document.getElementById("updateNow").onclick = applyUpdate;
      notifyUpdate(u);
    }
  }).catch(() => {});
}

function applyUpdate() {
  fetch("/api/update/apply" + q, { method: "POST" }).then(r => r.json()).then(res => {
    alert(res.ok ? "Updating omotam now - the page will disconnect for a few seconds." : "Update failed: " + res.error);
  }).catch(e => alert("Update failed: " + e));
}

function notifyUpdate(u) {
  try {
    if (window.Notification && Notification.permission === "granted") {
      const n = new Notification("omotam update available", {
        body: "Version " + u.latest + " is ready. Click to update.",
        tag: "omotam-update"
      });
      n.onclick = function () { window.focus(); applyUpdate(); };
    }
  } catch (e) {}
}

function _localInput(date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

function quickRange(minutes) {
  const to = new Date();
  const from = new Date(Date.now() - minutes * 60000);
  document.getElementById("qfrom").value = _localInput(from);
  document.getElementById("qto").value = _localInput(to);
  loadQueries();
}

function _rangeQuery() {
  const from = document.getElementById("qfrom").value;
  const to = document.getElementById("qto").value;
  let p = q ? q + "&" : "?";
  if (from) p += "since=" + Math.floor(new Date(from).getTime() / 1000) + "&";
  if (to) p += "until=" + Math.floor(new Date(to).getTime() / 1000) + "&";
  return p;
}

function setQMsg(text, good) {
  const m = document.getElementById("qmsg");
  m.textContent = text;
  m.className = good ? "ok" : "bad";
}

function loadQueries() {
  fetch("/api/queries" + _rangeQuery()).then(r => r.json()).then(res => {
    const rows = res.queries || [];
    document.getElementById("qcount").textContent = rows.length + " recorded request(s) in range";
    const tb = document.getElementById("qrows");
    tb.innerHTML = "";
    rows.slice().reverse().forEach(x => {
      const tr = document.createElement("tr");
      const cells = [
        new Date(x.ts * 1000).toLocaleString(), x.client, x.name, x.type, x.action, x.detail
      ];
      cells.forEach((v, i) => {
        const td = document.createElement("td");
        td.textContent = (v === undefined || v === null) ? "" : v;
        if (i !== 2 && i !== 5) td.className = "narrow";
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
    setQMsg("", true);
  }).catch(e => setQMsg("failed: " + e, false));
}

function exportQueries(fmt) {
  window.location = "/api/queries" + _rangeQuery() + "format=" + fmt;
}

function clearQueries() {
  fetch("/api/queries/clear" + q, { method: "POST" }).then(r => r.json()).then(() => {
    setQMsg("cleared", true);
    loadQueries();
  }).catch(e => setQMsg("failed: " + e, false));
}

function reload() {
  fetch("/api/reload" + q, { method:"POST" }).then(r => r.json()).then(res => {
    if (res.ok) { setMsg("reloaded from disk", true); load(); } else setMsg("error: " + res.error, false);
  });
}

let lastIndex = 0;

function setMsg2(text, good) {
  const m = document.getElementById("msg2");
  m.textContent = text;
  m.className = good ? "ok" : "bad";
}

function loadNotes() {
  fetch("/api/notes" + q).then(r => r.json()).then(res => {
    document.getElementById("notes").value = res.text || "";
    lastIndex = res.count || 0;
    setMsg2("", true);
  }).catch(e => setMsg2("load failed: " + e, false));
}

function saveNotes() {
  const text = document.getElementById("notes").value;
  fetch("/api/notes" + q, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ text: text }) })
    .then(r => r.json()).then(res => setMsg2(res.ok ? "saved at " + new Date().toLocaleTimeString() : ("error: " + res.error), res.ok))
    .catch(e => setMsg2("save failed: " + e, false));
}

function clearNotes() {
  const box = document.getElementById("notes");
  box.value = "";
  box.focus();
  setMsg2("cleared locally - press Save to persist", true);
}

function pollLog() {
  if (!document.getElementById("live").checked) return;
  const box = document.getElementById("notes");
  if (document.activeElement === box) return;  // do not disturb while typing
  const sep = TOKEN ? (q + "&") : "?";
  fetch("/api/log" + sep + "since=" + lastIndex).then(r => r.json()).then(res => {
    const lines = res.lines || [];
    if (!lines.length) { lastIndex = res.count || lastIndex; return; }
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
    let val = box.value;
    if (val && !val.endsWith("\n")) val += "\n";
    val += lines.join("\n") + "\n";
    box.value = val;
    lastIndex = res.count;
    if (atBottom) box.scrollTop = box.scrollHeight;
  }).catch(() => {});
}

load();
loadNotes();
quickRange(15);
pollLog();
setInterval(pollLog, 3000);
try { if (window.Notification && Notification.permission === "default") Notification.requestPermission(); } catch (e) {}
checkUpdate(false);
setInterval(function () { checkUpdate(false); }, 3600000);
</script>
</body>
</html>
"""


def record_to_api(name, value):
    """Raw config record -> normalized JSON-friendly {name, A, AAAA, TXT, CNAME, merge, block}."""
    rec = Resolver._normalize(value)
    return {
        "name": name,
        "A": rec["A"],
        "AAAA": rec["AAAA"],
        "TXT": rec["TXT"],
        "CNAME": rec["CNAME"],
        "merge": rec["merge"],
        "block": rec["block"],
    }


def api_to_raw(rec):
    """Normalized API record -> raw config value."""
    if rec.get("block"):
        return "BLOCK"
    out = {}
    for key in ("A", "AAAA", "TXT"):
        vals = rec.get(key)
        if vals:
            if isinstance(vals, str):
                vals = [vals]
            out[key] = [str(v) for v in vals]
    if rec.get("CNAME"):
        out["CNAME"] = str(rec["CNAME"]).rstrip(".")
    if rec.get("merge"):
        out["merge"] = True
    if not out:
        raise ValueError("record needs a value: A, AAAA, TXT, CNAME and/or block=true")
    return out


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


class GUIHandler(BaseHTTPRequestHandler):
    server_version = "CustomDNSGUI/1.0"

    def _auth_ok(self, query):
        tokens = [t for t in (STATE.config.get("api_token"), STATE.config.get("gui_token")) if t]
        if not tokens:
            return True
        supplied = query.get("token", [None])[0] or self.headers.get("X-API-Token") \
            or self.headers.get("X-Token") or ""
        auth = self.headers.get("Authorization", "")
        if not supplied and auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        return supplied in tokens

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _html(self, text, code=200):
        self._send(code, text.encode("utf-8"), "text/html; charset=utf-8")

    def _empty(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _public_config(self):
        c = STATE.config
        hostname = c.get("gui_hostname", "dns.settings")
        if isinstance(hostname, list):
            hostname = hostname[0] if hostname else "dns.settings"
        return {
            "upstream": c.get("upstream", "1.1.1.1"),
            "ttl": c.get("ttl", 60),
            "port": c.get("port", 53),
            "gui_port": c.get("gui_port", 8080),
            "tls": bool(c.get("gui_tls", False)),
            "tls_port": int(c.get("gui_tls_port", 443)),
            "hostname": hostname,
            "intercept_enabled": bool(c.get("intercept_enabled", False)),
            "intercept_ips": c.get("intercept_ips") or list(DEFAULT_INTERCEPT_IPS),
            "record_queries": bool(c.get("record_queries", False)),
            "revocation_crl": bool(c.get("revocation_crl", True)),
            "revocation_ocsp": bool(c.get("revocation_ocsp", False)),
            "update_check": bool(c.get("update_check", True)),
            "version": VERSION,
            "records": c.get("records", {}),
            "token_required": bool(c.get("gui_token")),
        }

    @staticmethod
    def _clean_ips(value):
        if isinstance(value, str):
            value = value.replace(",", " ").split()
        out = []
        for item in value or []:
            ip = str(item).strip()
            if ip:
                out.append(ip)
        return out

    def _merge(self, payload):
        c = dict(STATE.config)
        if "upstream" in payload:
            c["upstream"] = str(payload["upstream"]).strip()
        if "ttl" in payload:
            c["ttl"] = int(payload["ttl"])
        if "intercept_enabled" in payload:
            c["intercept_enabled"] = bool(payload["intercept_enabled"])
        if "intercept_ips" in payload:
            c["intercept_ips"] = self._clean_ips(payload["intercept_ips"])
        if "record_queries" in payload:
            c["record_queries"] = bool(payload["record_queries"])
        if "revocation_crl" in payload:
            c["revocation_crl"] = bool(payload["revocation_crl"])
        if "revocation_ocsp" in payload:
            c["revocation_ocsp"] = bool(payload["revocation_ocsp"])
        c.setdefault("intercept_ips", list(DEFAULT_INTERCEPT_IPS))
        c.setdefault("intercept_upstream", "9.9.9.10")
        if "records" in payload:
            if not isinstance(payload["records"], dict):
                raise ValueError("records must be an object")
            cleaned = {}
            for name, value in payload["records"].items():
                key = str(name).strip().lower().rstrip(".")
                if key:
                    cleaned[key] = value
            c["records"] = cleaned
        return c

    def _notes_path(self):
        base = os.path.dirname(os.path.abspath(STATE.path))
        return os.path.join(base, "dns_activity.txt")

    # ---------- central records API ----------

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("body must be a JSON object")
        return data

    @staticmethod
    def _path_name(path, prefix):
        from urllib.parse import unquote
        return unquote(path[len(prefix):]).strip().lower().rstrip(".")

    def _all_api_records(self):
        return {n: record_to_api(n, v) for n, v in STATE.config.get("records", {}).items()}

    def _api_status(self):
        r = STATE.resolver
        with QUERY_LOCK:
            query_count = len(QUERY_LOG)
        self._json({
            "ok": True,
            "listening_port": int(STATE.config.get("port", 53)),
            "upstream": r.upstream,
            "ttl": r.ttl,
            "record_count": len(STATE.config.get("records", {})),
            "gui_port": int(STATE.config.get("gui_port", 8080)),
            "tls": bool(STATE.config.get("gui_tls", False)),
            "central_resolver": bool(STATE.config.get("intercept_enabled", False)),
            "answer_addresses": list(r.intercept_ips),
            "record_queries": bool(r.record_queries),
            "recorded_query_count": query_count,
        })

    def _queries_in_range(self, query):
        def as_float(key, default):
            try:
                return float(query[key][0])
            except (KeyError, ValueError, IndexError):
                return default
        since = as_float("since", 0.0)
        until = as_float("until", time.time())
        try:
            limit = int(query["limit"][0])
        except (KeyError, ValueError, IndexError):
            limit = 5000
        with QUERY_LOCK:
            rows = [q for q in QUERY_LOG if since <= q["ts"] <= until]
        if limit > 0:
            rows = rows[-limit:]
        return rows

    def _api_queries(self, query):
        rows = self._queries_in_range(query)
        fmt = (query.get("format", ["json"])[0] or "json").lower()
        if fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["timestamp", "epoch", "client", "name", "type", "action", "detail"])
            for q in rows:
                writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(q["ts"])),
                    "{:.3f}".format(q["ts"]), q["client"], q["name"], q["type"], q["action"], q["detail"],
                ])
            body = buf.getvalue().encode("utf-8-sig")  # BOM so Excel reads UTF-8
            name = "dns-recording-{}.csv".format(time.strftime("%Y%m%d-%H%M%S"))
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(name))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json({"ok": True, "count": len(rows), "queries": rows})

    def _apply_record(self, name, payload, append):
        name = (name or "").strip().lower().rstrip(".")
        if not name:
            self._json({"ok": False, "error": "missing domain name"}, 400)
            return
        fields = {k: payload.get(k) for k in ("A", "AAAA", "TXT", "CNAME", "merge", "block")}
        if append:
            existing = STATE.config.get("records", {}).get(name)
            cur = record_to_api(name, existing) if existing is not None else \
                {"A": [], "AAAA": [], "TXT": [], "CNAME": None, "merge": False, "block": False}
            fields = {
                "A": cur["A"] + _as_list(fields["A"]),
                "AAAA": cur["AAAA"] + _as_list(fields["AAAA"]),
                "TXT": cur["TXT"] + _as_list(fields["TXT"]),
                "CNAME": fields["CNAME"] if fields["CNAME"] is not None else cur["CNAME"],
                "merge": bool(fields["merge"]) if fields["merge"] is not None else cur["merge"],
                "block": bool(fields["block"]) if fields["block"] is not None else cur["block"],
            }
        try:
            raw = api_to_raw(fields)
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, 400)
            return
        STATE.upsert_record(name, raw)
        log("record {} for {} via API".format("merged" if append else "replaced", name))
        self._json({"ok": True, "record": record_to_api(name, raw)})

    # ---------- revocation (CRL / OCSP) ----------

    def _serve_crl(self, path):
        paths = resolve_paths(STATE.config, STATE.path)
        if path == "/crl.pem":
            file, ctype = paths["crl"] + ".pem", "application/x-pem-file"
        else:
            file, ctype = paths["crl"] + ".der", "application/pkix-crl"
        if not os.path.exists(file):
            self._empty(404)
            return
        with open(file, "rb") as fh:
            self._send(200, fh.read(), ctype)

    def _serve_ocsp(self, body):
        if not STATE.config.get("revocation_ocsp", False):
            self._empty(404)
            return
        paths = resolve_paths(STATE.config, STATE.path)
        der = build_ocsp_response(body, paths)
        if der is None:
            self._empty(500)
            return
        self._send(200, der, "application/ocsp-response")

    def _handle_revocation(self, path, query):
        """Return True if the request was a CRL/OCSP fetch."""
        if path in ("/crl", "/crl.der", "/crl.pem"):
            self._serve_crl(path)
            return True
        if path == "/ocsp":
            if self.command == "POST":
                length = int(self.headers.get("Content-Length", 0))
                self._serve_ocsp(self.rfile.read(length) if length else b"")
            else:
                # OCSP over GET: base64 of the request in the path or query
                import base64
                raw = path[len("/ocsp"):].lstrip("/")
                if not raw:
                    values = list(query.values())
                    raw = values[0][0] if values and values[0] else ""
                try:
                    self._serve_ocsp(base64.b64decode(raw))
                except Exception:  # noqa: BLE001
                    self._empty(400)
            return True
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path.startswith("/crl") or parsed.path == "/ocsp":
            self._handle_revocation(parsed.path, query)
            return
        if not self._auth_ok(query):
            self._empty(401)
            return
        if parsed.path in ("/", "/index.html"):
            token = STATE.config.get("gui_token") or ""
            self._html(GUI_HTML.replace("__TOKEN__", json.dumps(token)))
        elif parsed.path == "/api/config":
            self._json(self._public_config())
        elif parsed.path == "/api/log":
            since = 0
            if "since" in query:
                try:
                    since = int(query["since"][0])
                except (ValueError, IndexError):
                    since = 0
            with LOG_LOCK:
                lines = list(LOG_BUFFER)
                total = LOG_TOTAL
            oldest = total - len(lines)
            if since < oldest:
                since = oldest
            self._json({"lines": lines[since - oldest:], "count": total})
        elif parsed.path == "/api/notes":
            path = self._notes_path()
            text = ""
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            with LOG_LOCK:
                total = LOG_TOTAL
            self._json({"text": text, "count": total})
        elif parsed.path == "/api/status":
            self._api_status()
        elif parsed.path == "/api/queries":
            self._api_queries(query)
        elif parsed.path == "/api/update":
            self._json(get_update_status())
        elif parsed.path == "/api/records":
            self._json({"ok": True, "records": self._all_api_records()})
        elif parsed.path.startswith("/api/records/"):
            name = self._path_name(parsed.path, "/api/records/")
            value = STATE.config.get("records", {}).get(name)
            if value is None:
                self._json({"ok": False, "error": "record not found", "name": name}, 404)
            else:
                self._json({"ok": True, "record": record_to_api(name, value)})
        else:
            self._empty(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/ocsp":
            self._handle_revocation(parsed.path, query)
            return
        if not self._auth_ok(query):
            self._empty(401)
            return
        if parsed.path == "/api/config":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                config = self._merge(payload)
                STATE.save(config)
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            log("config updated via web GUI ({} override(s))".format(len(config.get("records", {}))))
            sync_interception(STATE.config)
            refresh_crypto()
            self._json({"ok": True, "config": self._public_config()})
        elif parsed.path == "/api/notes":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                text = payload.get("text", "")
                if not isinstance(text, str):
                    raise ValueError("text must be a string")
                path = self._notes_path()
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(tmp, path)
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            log("activity notes saved ({} chars)".format(len(text)))
            self._json({"ok": True})
        elif parsed.path == "/api/reload":
            try:
                STATE.load_from_disk()
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 500)
                return
            log("config reloaded from disk")
            self._json({"ok": True, "config": self._public_config()})
        elif parsed.path == "/api/records":
            try:
                payload = self._read_json()
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            self._apply_record(payload.get("name", ""), payload, append=False)
        elif parsed.path.startswith("/api/records/"):
            try:
                payload = self._read_json()
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            self._apply_record(self._path_name(parsed.path, "/api/records/"), payload, append=True)
        elif parsed.path == "/api/settings":
            try:
                payload = self._read_json()
                settings = {}
                if "upstream" in payload:
                    settings["upstream"] = str(payload["upstream"]).strip()
                if "upstream_port" in payload:
                    settings["upstream_port"] = int(payload["upstream_port"])
                if "ttl" in payload:
                    settings["ttl"] = int(payload["ttl"])
                if "intercept_ips" in payload:
                    settings["intercept_ips"] = self._clean_ips(payload["intercept_ips"])
                if "record_queries" in payload:
                    settings["record_queries"] = bool(payload["record_queries"])
                STATE.patch_settings(**settings)
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            log("settings updated via API: {}".format(settings))
            if "intercept_ips" in settings:
                sync_interception(STATE.config)
            self._json({"ok": True, "settings": {
                "upstream": STATE.resolver.upstream,
                "ttl": STATE.resolver.ttl,
                "answer_addresses": list(STATE.resolver.intercept_ips),
                "record_queries": STATE.resolver.record_queries}})
        elif parsed.path == "/api/queries/clear":
            with QUERY_LOCK:
                QUERY_LOG.clear()
            log("recorded DNS queries cleared via API")
            self._json({"ok": True, "count": 0})
        elif parsed.path == "/api/update/check":
            try:
                self._json(check_updates())
            except Exception as exc:  # noqa: BLE001
                self._json({"ok": False, "error": str(exc)}, 500)
        elif parsed.path == "/api/update/apply":
            ok, info = run_updater()
            if ok:
                log("update started via updater script")
                self._json({"ok": True, "started": info})
            else:
                self._json({"ok": False, "error": info}, 500)
        else:
            self._empty(404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if not self._auth_ok(parse_qs(parsed.query)):
            self._empty(401)
            return
        if parsed.path.startswith("/api/records/"):
            try:
                payload = self._read_json()
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
                return
            self._apply_record(self._path_name(parsed.path, "/api/records/"), payload, append=False)
        else:
            self._empty(404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if not self._auth_ok(parse_qs(parsed.query)):
            self._empty(401)
            return
        if parsed.path.startswith("/api/records/"):
            name = self._path_name(parsed.path, "/api/records/")
            if STATE.delete_record(name):
                log("record deleted for {} via API".format(name))
                self._json({"ok": True, "deleted": name})
            else:
                self._json({"ok": False, "error": "record not found", "name": name}, 404)
        else:
            self._empty(404)

    def log_message(self, fmt, *args):
        pass


class ThreadedGUI(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


TLS_GUI = None
TLS_BIND = "0.0.0.0"
TLS_PORT = 443


def start_tls_server(config, paths):
    """Create (or recreate) the HTTPS GUI listener with a fresh certificate."""
    global TLS_GUI, TLS_BIND, TLS_PORT
    if TLS_GUI is not None:
        try:
            TLS_GUI.shutdown()
            TLS_GUI.server_close()
        except Exception:  # noqa: BLE001
            pass
        TLS_GUI = None
    TLS_BIND = config.get("gui_bind", "0.0.0.0")
    TLS_PORT = int(config.get("gui_tls_port", 443))
    ctx = make_ssl_context(paths["cert"], paths["key"])
    gui = ThreadedGUI((TLS_BIND, TLS_PORT), GUIHandler)
    gui.socket = ctx.wrap_socket(gui.socket, server_side=True)
    threading.Thread(target=gui.serve_forever, daemon=True).start()
    TLS_GUI = gui
    return gui


def refresh_crypto(reload_tls=True):
    """Re-issue the cert/CRL as needed and (re)load the HTTPS listener."""
    if STATE is None:
        return
    config = STATE.config
    paths = resolve_paths(config, STATE.path)
    try:
        ensure_certificates(paths, config)
    except Exception as exc:  # noqa: BLE001
        log("certificate refresh failed: {}".format(exc))
        return
    if config.get("revocation_crl", True):
        try:
            generate_crl(paths, config)
        except Exception as exc:  # noqa: BLE001
            log("CRL generation failed: {}".format(exc))
    if reload_tls and config.get("gui_tls", False):
        try:
            start_tls_server(config, paths)
            log("HTTPS reloaded (CRL={}, OCSP={})".format(
                config.get("revocation_crl", True), config.get("revocation_ocsp", False)))
        except Exception as exc:  # noqa: BLE001
            log("HTTPS reload failed: {}".format(exc))


DEFAULT_CONFIG = {
    "upstream": "1.1.1.1",
    "upstream_port": 53,
    "port": 53,
    "bind": "0.0.0.0",
    "ttl": 60,
    "gui_enabled": True,
    "gui_bind": "0.0.0.0",
    "gui_port": 8080,
    "gui_tls": True,
    "gui_tls_port": 443,
    "gui_hostname": "dns.settings",
    "gui_cert": "dns.settings.crt",
    "gui_key": "dns.settings.key",
    "gui_ca": "dns.settings-ca.crt",
    "gui_ca_key": "dns.settings-ca.key",
    "gui_token": None,
    "revocation_crl": True,
    "revocation_ocsp": False,
    "intercept_enabled": False,
    "intercept_ips": list(DEFAULT_INTERCEPT_IPS),
    "intercept_upstream": "9.9.9.10",
    "record_queries": False,
    "update_check": True,
    "update_check_hours": 6,
    "records": {
        "example.local": "192.168.1.50",
        "*.home.lan": {"A": "192.168.1.60", "AAAA": "fd00::60"},
        "blocked.example.com": "BLOCK",
        "alias.example.local": {"CNAME": "example.local"},
        "myexample.com": {"TXT": "hello-world", "merge": True},
    },
}


def load_config(path):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(DEFAULT_CONFIG, fh, indent=2)
        log("no config found, wrote default to {}".format(path))
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def run_test(config, name, qtype_name):
    qtype = QTYPE_BY_NAME.get(qtype_name.upper(), 1)
    tid = 0x1234
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    packet = header + question
    host = config.get("bind", "0.0.0.0")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    port = int(config.get("port", 53))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(packet, (host, port))
    resp, _ = sock.recvfrom(65535)
    _, flags, qd, an, _, _ = struct.unpack("!HHHHHH", resp[:12])
    print("response: rcode={} answers={}".format(flags & 0x0F, an))
    off = 12
    _, off = parse_name(resp, off)
    off += 4
    for _ in range(an):
        _, off = parse_name(resp, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", resp[off:off + 10])
        off += 10
        rdata = resp[off:off + rdlen]
        off += rdlen
        if rtype == 1:
            val = socket.inet_ntoa(rdata)
        elif rtype == 28:
            val = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            val, _ = parse_name(resp, off - rdlen)
        else:
            val = rdata.hex()
        print("  {} {} TTL={} {}".format(QTYPES.get(rtype, rtype), rclass, ttl, val))


def main():
    global STATE
    parser = argparse.ArgumentParser(description="Custom DNS server for a local network")
    parser.add_argument("--config", default="dns_hosts.json", help="path to JSON config")
    parser.add_argument("--port", type=int, default=None, help="override listen port")
    parser.add_argument("--bind", default=None, help="override bind address")
    parser.add_argument("--gui-port", type=int, default=None, help="override web GUI port")
    parser.add_argument("--gui-bind", default=None, help="override web GUI bind address")
    parser.add_argument("--no-gui", action="store_true", help="disable the web GUI")
    parser.add_argument("--no-tls", action="store_true", help="disable HTTPS for the web GUI")
    parser.add_argument("--no-update-check", action="store_true", help="disable background update checks")
    parser.add_argument("--ensure-cert", action="store_true", help="generate the TLS certificate if missing, then exit")
    parser.add_argument("--print-ca", action="store_true", help="print the CA certificate path, then exit")
    parser.add_argument("--test", metavar="DOMAIN", help="send a test query and exit")
    parser.add_argument("--type", default="A", help="query type for --test (default A)")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.port is not None:
        config["port"] = args.port
    if args.bind is not None:
        config["bind"] = args.bind
    if args.gui_port is not None:
        config["gui_port"] = args.gui_port
    if args.gui_bind is not None:
        config["gui_bind"] = args.gui_bind
    if args.no_tls:
        config["gui_tls"] = False

    paths = resolve_paths(config, args.config)

    if args.ensure_cert:
        try:
            created = ensure_certificates(paths, config)
            if config.get("revocation_crl", True):
                generate_crl(paths, config)
        except Exception as exc:
            log("certificate generation failed: {}".format(exc))
            sys.exit(1)
        log("TLS certificate {} ({})".format("created" if created else "already present", paths["cert"]))
        print(paths["ca"])
        return
    if args.print_ca:
        print(paths["ca"])
        return

    if args.test:
        try:
            run_test(config, args.test, args.type)
        except Exception as exc:
            print("test failed: {}".format(exc))
            sys.exit(1)
        return

    if config.get("gui_enabled", True) and config.get("gui_add_dns_record", True):
        hostnames = paths["hostnames"]
        ip = config.get("gui_record_ip") or detect_lan_ip(config.get("intercept_ips"))
        for h in hostnames:
            config.setdefault("records", {})[h] = ip

    STATE = State(args.config, config)
    bind = config.get("bind", "0.0.0.0")
    port = int(config.get("port", 53))

    if config.get("intercept_enabled", False):
        log("override mode ON: hijacking {}".format(", ".join(STATE.resolver.intercept_ips)))
        if STATE.resolver.upstream_overridden:
            log("override mode: forwarder switched to {} to avoid a loop".format(STATE.resolver.upstream))
        if STATE.resolver.block_doh:
            log("override mode: DoH providers will be blocked (NXDOMAIN) to force fallback")
        sync_interception(config)

    log("custom DNS server starting")
    log("records : {} override(s), TTL {}s".format(len(STATE.resolver.records), config.get("ttl", 60)))
    for name, rec in STATE.resolver.records.items():
        if rec["block"]:
            target = "BLOCK(NXDOMAIN)"
        elif rec["CNAME"]:
            target = "CNAME " + rec["CNAME"]
        else:
            bits = rec["A"] + rec["AAAA"] + rec["TXT"]
            target = " ".join(bits)
            if rec["merge"]:
                target += "  [passthrough]"
        log("  {:32s} {}".format(name, target))
    log("upstream: {}:{}".format(STATE.resolver.upstream, STATE.resolver.upstream_port))

    gui_servers = []

    if config.get("update_check", True) and not args.no_update_check:
        threading.Thread(target=update_checker_loop, args=(config,), daemon=True).start()

    if config.get("gui_enabled", True) and not args.no_gui:
        gui_bind = config.get("gui_bind", "0.0.0.0")
        token = config.get("gui_token")
        suffix = "?token=" + token if token else ""

        if config.get("gui_tls", False):
            try:
                created = ensure_certificates(paths, config)
                if created:
                    log("issued TLS certificate for {}".format(", ".join(paths["hostnames"])))
                if config.get("revocation_crl", True):
                    generate_crl(paths, config)
                gui = start_tls_server(config, paths)
                gui_servers.append(gui)
                host = paths["hostnames"][0] if paths["hostnames"] else "127.0.0.1"
                tls_port = int(config.get("gui_tls_port", 443))
                url_host = host if tls_port == 443 else "{}:{}".format(host, tls_port)
                log("web GUI: https://{}/{}".format(url_host, suffix))
                log("revocation: CRL={} OCSP={}".format(
                    config.get("revocation_crl", True), config.get("revocation_ocsp", False)))
            except Exception as exc:
                log("could not start HTTPS GUI -> {}".format(exc))

        if not config.get("gui_tls", False) or config.get("gui_http_also", True):
            gui_port = int(config.get("gui_port", 8080))
            try:
                gui = ThreadedGUI((gui_bind, gui_port), GUIHandler)
            except OSError as exc:
                log("could not start HTTP GUI on {}:{} -> {}".format(gui_bind, gui_port, exc))
            else:
                threading.Thread(target=gui.serve_forever, daemon=True).start()
                gui_servers.append(gui)
                shown = "127.0.0.1" if gui_bind == "0.0.0.0" else gui_bind
                log("web GUI: http://{}:{}/{}".format(shown, gui_port, suffix))

    try:
        udp = ThreadedUDP((bind, port), UDPHandler)
        tcp = ThreadedTCP((bind, port), TCPHandler)
    except PermissionError:
        log("permission denied binding {}:{}".format(bind, port))
        log("run this as Administrator, or pick a high port like --port 5353")
        sys.exit(1)
    except OSError as exc:
        log("could not bind {}:{} -> {}".format(bind, port, exc))
        sys.exit(1)

    extra_servers = []
    if bind in ("0.0.0.0", "::", ""):
        try:
            udp6 = ThreadedUDP6(("::", port), UDPHandler)
            tcp6 = ThreadedTCP6(("::", port), TCPHandler)
            extra_servers += [udp6, tcp6]
        except OSError as exc:
            log("IPv6 listeners not available ({}), continuing IPv4-only".format(exc))

    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    for srv in extra_servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    if extra_servers:
        log("listening on {}:{} (UDP+TCP, IPv4+IPv6)".format(bind, port))
    else:
        log("listening on {}:{} (UDP+TCP)".format(bind, port))
    try:
        udp.serve_forever()
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        for srv in [udp, tcp] + extra_servers:
            srv.shutdown()
        for gui in gui_servers:
            gui.shutdown()


if __name__ == "__main__":
    main()
