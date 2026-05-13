#!/usr/bin/env -S pipx run
# /// script
# requires-python = ">=3.11"
# dependencies = ["dnspython"]
# ///
"""
sslscan_audit.py — TLS configuration auditor built on sslscan

Sister tool to sha1scan.py.  Where sha1scan focuses narrowly on SHA-1 MAC
cipher suites via nmap NSE, this tool drives `sslscan --xml=-` against every
(hostname|IP, port) pair to produce a full TLS posture report:

  * Enabled / disabled protocol versions (SSLv2/v3, TLS 1.0–1.3)
  * Every accepted cipher suite with key size, ECDHE curve and bit strength
  * Supported TLS 1.3 / 1.2 key-exchange groups, including post-quantum
    (PQ) hybrid groups such as X25519MLKEM768 and X25519Kyber768Draft00
  * Certificate details (subject, altnames, issuer, sig algo, validity)
  * Vulnerability flags: Heartbleed, insecure renegotiation, CRIME (TLS
    compression), TLS_FALLBACK_SCSV support
  * Per-cipher and per-protocol weakness classification
  * Per-endpoint post-quantum handshake readiness

XML parsing is exact — no scraping of human-readable sslscan output.

Usage:
  sslscan_audit.py [--cidr CIDR ...] [--domains FILE] [--ports PORT ...] \\
                   [--workers N] [--format md csv json] [--output STEM]
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

import dns.resolver
import dns.exception

# ---------------------------------------------------------------------------
# Constants & discovery
# ---------------------------------------------------------------------------

DEFAULT_PORTS = [443, 8443, 465, 993, 995]
DEFAULT_WORKERS = 20
DEFAULT_CONNECT_TIMEOUT = 5   # seconds, passed to sslscan --connect-timeout
DEFAULT_SOCKET_TIMEOUT  = 5   # seconds, passed to sslscan --timeout
SUBPROC_TIMEOUT_FACTOR  = 12  # subprocess wall-clock = factor * socket_timeout + 30

# Tool version — bump when the report schema or scoring logic changes.
SCRIPT_VERSION = "0.3.0"

# Mutable runtime config (set in main() so we don't have to plumb it through
# every helper).  STRICT_PQ promotes "no PQ key-exchange" to a finding;
# MIN_SCORE_RANK promotes "endpoint scored below this sslscan label" to a finding.
STRICT_PQ = False
MIN_SCORE_RANK: int | None = None   # None disables the gate

# Weak protocols (always flagged)
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

# Cipher-name regex tags. sslscan reports OpenSSL names like
#   ECDHE-RSA-AES128-SHA  or  AES256-SHA256
# and (for TLS 1.3) IANA names like TLS_AES_128_GCM_SHA256.
RE_SHA1   = re.compile(r"(?:_SHA$|-SHA$)")              # SHA-1 MAC
RE_CBC    = re.compile(r"(?:-CBC-|_CBC_|-AES\d+-(?!GCM)|-CAMELLIA\d+-(?!GCM))")
RE_RC4    = re.compile(r"RC4", re.I)
RE_DES    = re.compile(r"\bDES\b|3DES|DES-CBC3", re.I)
RE_EXPORT = re.compile(r"EXP(?:ORT)?", re.I)
RE_NULL   = re.compile(r"(?:^|[-_])NULL(?:[-_]|$)", re.I)
RE_ANON   = re.compile(r"(?:^|[-_])(?:ADH|AECDH|anon)(?:[-_]|$)", re.I)
RE_NO_PFS = re.compile(r"^(?:AES|RSA|DES|RC4|CAMELLIA|ARIA)")   # cipher starts with bulk-only → RSA kex, no PFS

# Post-Quantum (PQ) key-exchange group detector.
# Matches IANA-registered hybrid + pure-PQ named groups that sslscan reports
# in TLS 1.3 (and a few pre-standard codepoints still seen in the wild):
#   * X25519MLKEM768            (IANA 0x11EC — RFC 9606 hybrid, the upcoming standard)
#   * SecP256r1MLKEM768         (IANA 0x11EB)
#   * MLKEM512 / MLKEM768 / MLKEM1024 (pure ML-KEM, FIPS 203)
#   * X25519Kyber768Draft00     (0x6399, Cloudflare/Google deployment from 2022-2024)
#   * SecP256r1Kyber768Draft00  (0x639A)
#   * Older Kyber* draft codepoints that some servers still negotiate
RE_PQ_GROUP = re.compile(r"(?:MLKEM|Kyber|ML-?KEM)", re.I)

# Post-Quantum signature algorithm detector for X.509 certificates.
# Matches the NIST PQ signature standards and well-known finalists/drafts:
#   * ML-DSA-44 / ML-DSA-65 / ML-DSA-87  (FIPS 204, Dilithium)
#   * SLH-DSA-* (FIPS 205, SPHINCS+)
#   * Falcon-512 / Falcon-1024 (FN-DSA candidate)
#   * Dilithium* / SPHINCS+* (pre-standard names still on some pilot CAs)
RE_PQ_SIG = re.compile(
    r"(?:ML-?DSA|SLH-?DSA|Dilithium|SPHINCS|Falcon|FN-?DSA)",
    re.I,
)

# sslscan strength labels in ascending order of safety.
# Used to compute a per-port "worst observed strength" — analogous to an
# SSL Labs grade rollup, only computed from sslscan's own classifier so we
# never invent a grading system.  Unknown labels sort *worse* than null so
# we never accidentally upgrade an unfamiliar string.
STRENGTH_ORDER = {
    "null":       0,
    "anonymous":  1,
    "weak":       2,
    "medium":     3,
    "acceptable": 4,
    "good":       5,
    "strong":     6,
}
STRENGTH_BUCKETS = list(STRENGTH_ORDER.keys())   # ordered worst → best

log = logging.getLogger("sslscan_audit")


def _find_sslscan() -> str:
    path = shutil.which("sslscan")
    if path:
        return path
    if platform.system() == "Windows":
        for pf in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                   os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            exe = Path(pf) / "sslscan" / "sslscan.exe"
            if exe.is_file():
                return str(exe)
    for cand in ("/usr/local/bin/sslscan", "/usr/bin/sslscan"):
        if Path(cand).is_file():
            return cand
    raise RuntimeError(
        "sslscan not found. Install from https://github.com/rbsec/sslscan "
        "or your distribution's package manager."
    )


def _strength_rank(label: str) -> int:
    """Ordinal rank for a sslscan strength label. Unknown → -1 (treated as worst)."""
    return STRENGTH_ORDER.get((label or "").lower(), -1)


def _worst_strength(labels: list[str]) -> str:
    """Return the label with the lowest rank from a list, or '' if empty."""
    if not labels:
        return ""
    return min(labels, key=_strength_rank)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Cipher:
    status: str            # "preferred" | "accepted"
    protocol: str          # "TLSv1.2" etc.
    name: str
    bits: int
    cipher_id: str
    strength: str          # sslscan's own label: strong/acceptable/weak/null
    curve: str = ""
    ecdhe_bits: str = ""
    dhe_bits: str = ""

    def weaknesses(self) -> list[str]:
        tags: list[str] = []
        n = self.name
        if RE_NULL.search(n):    tags.append("NULL")
        if RE_ANON.search(n):    tags.append("ANON")
        if RE_EXPORT.search(n):  tags.append("EXPORT")
        if RE_DES.search(n):     tags.append("DES/3DES")
        if RE_RC4.search(n):     tags.append("RC4")
        if RE_SHA1.search(n) and not n.startswith("TLS_"):
            # TLS 1.3 IANA suites end in _SHA256/_SHA384 — exclude false matches by
            # requiring non-IANA prefix; the regex already enforces "_SHA$"/"-SHA$".
            tags.append("SHA1-MAC")
        if RE_CBC.search(n) and self.protocol in {"TLSv1.0", "TLSv1.1"}:
            tags.append("CBC-OLD-TLS")
        if RE_NO_PFS.match(n) and self.protocol != "TLSv1.3":
            tags.append("NO-PFS")
        return tags


@dataclass
class KexGroup:
    protocol: str
    name: str
    bits: int
    strength: str

    def is_pq(self) -> bool:
        """True if this is a post-quantum or PQ-hybrid named group."""
        return bool(RE_PQ_GROUP.search(self.name))

    def is_hybrid_pq(self) -> bool:
        """True if a PQ KEM is combined with a classical curve (the
        recommended deployment for the foreseeable future)."""
        n = self.name
        if not RE_PQ_GROUP.search(n):
            return False
        return bool(re.search(r"(?:x25519|x448|secp\d+r1|p-?\d{3})", n, re.I))


@dataclass
class Certificate:
    subject: str = ""
    altnames: str = ""
    issuer: str = ""
    signature_algorithm: str = ""
    pk_type: str = ""
    pk_bits: str = ""
    pk_curve: str = ""
    self_signed: str = ""
    not_before: str = ""
    not_after: str = ""
    expired: str = ""

    def is_pq_signed(self) -> bool:
        """True if the cert is signed with a post-quantum signature algorithm
        (ML-DSA, SLH-DSA, Falcon, etc. — including pre-standard names)."""
        return bool(RE_PQ_SIG.search(self.signature_algorithm or ""))


@dataclass
class PortResult:
    port: int
    reachable: bool = False
    protocols: dict[str, bool] = field(default_factory=dict)   # "TLSv1.2" -> True/False
    ciphers: list[Cipher] = field(default_factory=list)
    groups: list[KexGroup] = field(default_factory=list)
    cert: Certificate = field(default_factory=Certificate)
    heartbleed_vulnerable: list[str] = field(default_factory=list)   # protos that are vulnerable
    renegotiation_supported: str = ""
    renegotiation_secure: str = ""
    compression_supported: str = ""
    fallback_supported: str = ""
    error: str = ""

    # ---- derived helpers ----------------------------------------------------
    def enabled_protocols(self) -> list[str]:
        return [p for p, enabled in self.protocols.items() if enabled]

    def weak_protocols(self) -> list[str]:
        return [p for p in self.enabled_protocols() if p in WEAK_PROTOCOLS]

    def weak_ciphers(self) -> list[tuple[Cipher, list[str]]]:
        out = []
        for c in self.ciphers:
            w = c.weaknesses()
            if w:
                out.append((c, w))
        return out

    def pq_groups(self) -> list[KexGroup]:
        """All advertised post-quantum (or PQ-hybrid) key-exchange groups."""
        return [g for g in self.groups if g.is_pq()]

    def pq_kex_supported(self) -> bool:
        return bool(self.pq_groups())

    def pq_kex_kind(self) -> str:
        """Best PQ posture for this endpoint:
           'hybrid' (PQ + classical), 'pure-pq', 'none'."""
        pq = self.pq_groups()
        if not pq:
            return "none"
        if any(g.is_hybrid_pq() for g in pq):
            return "hybrid"
        return "pure-pq"

    # ---- sslscan strength rollups ------------------------------------------
    def worst_cipher_strength(self) -> str:
        """Worst sslscan strength label observed across all accepted ciphers."""
        return _worst_strength([c.strength for c in self.ciphers if c.strength])

    def worst_group_strength(self) -> str:
        """Worst sslscan strength label observed across all key-exchange groups."""
        return _worst_strength([g.strength for g in self.groups if g.strength])

    def overall_strength(self) -> str:
        """Worst label across both ciphers and groups — a single rollup the
        sslscan engine itself produces; equivalent to 'as weak as the
        weakest negotiable primitive on this port'."""
        return _worst_strength(
            [c.strength for c in self.ciphers if c.strength]
            + [g.strength for g in self.groups if g.strength]
        )

    def cipher_strength_distribution(self) -> dict[str, int]:
        """Count of ciphers by sslscan strength label (only known buckets)."""
        out: dict[str, int] = {b: 0 for b in STRENGTH_BUCKETS}
        for c in self.ciphers:
            label = (c.strength or "").lower()
            if label in out:
                out[label] += 1
        return out

    def has_findings(self) -> bool:
        base = (
            bool(self.weak_protocols())
            or bool(self.weak_ciphers())
            or bool(self.heartbleed_vulnerable)
            or self.compression_supported == "1"
            or (self.renegotiation_supported == "1" and self.renegotiation_secure == "0")
        )
        if base:
            return True
        if STRICT_PQ and not self.pq_kex_supported():
            return True
        if MIN_SCORE_RANK is not None and self.overall_strength():
            if _strength_rank(self.overall_strength()) < MIN_SCORE_RANK:
                return True
        return False


@dataclass
class HostResult:
    target: str
    ip: str
    source: str                # "domain" | "cidr"
    cname_chain: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    ports: dict[int, PortResult] = field(default_factory=dict)

    def reachable_ports(self) -> list[PortResult]:
        return [p for p in self.ports.values() if p.reachable]

    def has_findings(self) -> bool:
        return any(p.has_findings() for p in self.reachable_ports())

    def pq_kex_kind(self) -> str:
        """Best PQ posture across all reachable ports for this host."""
        kinds = {p.pq_kex_kind() for p in self.reachable_ports()}
        if "hybrid" in kinds:
            return "hybrid"
        if "pure-pq" in kinds:
            return "pure-pq"
        return "none"

    def overall_strength(self) -> str:
        """Worst sslscan strength rollup across all reachable ports."""
        labels = [p.overall_strength() for p in self.reachable_ports()
                  if p.overall_strength()]
        return _worst_strength(labels)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit TLS configuration across domains and subnets using sslscan.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--cidr", nargs="+", metavar="CIDR",
                   help="One or more subnets in CIDR notation.")
    p.add_argument("--domains", metavar="FILE",
                   help="File with one domain per line (# and blank lines ignored).")
    p.add_argument("--ports", nargs="+", type=int, default=DEFAULT_PORTS,
                   help="TLS ports to probe.")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   help="Max parallel sslscan processes.")
    p.add_argument("--connect-timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT,
                   dest="connect_timeout",
                   help="sslscan --connect-timeout (TCP connect, seconds).")
    p.add_argument("--socket-timeout", type=int, default=DEFAULT_SOCKET_TIMEOUT,
                   dest="socket_timeout",
                   help="sslscan --timeout (per-socket I/O, seconds).")
    p.add_argument("--sslscan-path", metavar="PATH",
                   help="Path to sslscan; auto-detected from PATH otherwise.")
    p.add_argument("--iana-names", action="store_true",
                   help="Pass --iana-names to sslscan (RFC cipher names).")
    p.add_argument("--show-times", action="store_true",
                   help="Include handshake-time data (sslscan --show-times).")
    p.add_argument("--strict-pq", action="store_true",
                   help="Treat endpoints without any post-quantum key-exchange "
                        "group as findings (exit non-zero, sort to top of "
                        "endpoint details, count in flagged total). Use this in "
                        "CI to enforce PQ readiness across a fleet.")
    p.add_argument("--min-score", metavar="LABEL",
                   choices=STRENGTH_BUCKETS, default=None,
                   help="Treat any endpoint whose overall sslscan strength score "
                        "is below this label as a finding (exit non-zero). "
                        f"Choices, worst→best: {', '.join(STRENGTH_BUCKETS)}. "
                        "Use this in CI as a fleet-wide minimum bar.")
    p.add_argument("--format", nargs="+",
                   choices=["md", "csv", "json", "html"], default=["md"],
                   help="One or more output formats.")
    p.add_argument("--output", metavar="STEM",
                   help="Output destination. With multiple --format values this is "
                        "used as a stem and extensions are appended.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable DEBUG logging.")
    args = p.parse_args()
    if not args.cidr and not args.domains:
        p.error("at least one of --cidr or --domains is required")
    return args


# ---------------------------------------------------------------------------
# Domains & DNS
# ---------------------------------------------------------------------------

def load_domains(filepath: str) -> list[str]:
    out: list[str] = []
    with open(filepath) as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _resolve_cname_chain(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    chain: list[str] = []
    current = domain
    seen = {domain.lower()}
    for _ in range(10):
        try:
            ans = resolver.resolve(current, "CNAME")
            target = str(ans[0].target).rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            break
        if target.lower() in seen:
            break
        chain.append(target)
        seen.add(target.lower())
        current = target
    return chain


def _resolve_a(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        ans = resolver.resolve(domain, "A")
        return [str(rr) for rr in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        log.warning("DNS A lookup failed for %s: %s", domain, exc)
        return []


def resolve_all_domains(domains: list[str]) -> dict[str, tuple[list[str], list[str]]]:
    """domain -> (cname_chain, [ip,...])."""
    resolver = dns.resolver.Resolver()
    out: dict[str, tuple[list[str], list[str]]] = {}
    for d in domains:
        chain = _resolve_cname_chain(d, resolver)
        ips = _resolve_a(d, resolver)
        if not ips:
            log.warning("No A records for %s — skipping", d)
        out[d] = (chain, ips)
    return out


# ---------------------------------------------------------------------------
# sslscan invocation
# ---------------------------------------------------------------------------

def build_sslscan_cmd(
    sslscan: str,
    *,
    target_ip: str,
    port: int,
    sni: str | None,
    connect_timeout: int,
    socket_timeout: int,
    iana_names: bool,
    show_times: bool,
) -> list[str]:
    """One sslscan invocation against (target_ip, port).

    We always target the IP literal so that for round-robin DNS each A record
    is scanned individually; --sni-name carries the original hostname so the
    server returns the right virtualhost / certificate.
    """
    cmd: list[str] = [
        sslscan,
        "--xml=-",
        "--no-colour",
        f"--connect-timeout={connect_timeout}",
        f"--timeout={socket_timeout}",
        "--show-certificate",
    ]
    if sni:
        cmd.append(f"--sni-name={sni}")
    if iana_names:
        cmd.append("--iana-names")
    if show_times:
        cmd.append("--show-times")
    cmd.append(f"{target_ip}:{port}")
    return cmd


def run_sslscan(cmd: list[str], label: str, proc_timeout: int) -> str | None:
    log.debug("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=proc_timeout)
    except subprocess.TimeoutExpired:
        log.warning("sslscan subprocess hard-timeout (%ds) for %s", proc_timeout, label)
        return None
    except OSError as exc:
        log.error("Failed to launch sslscan: %s", exc)
        return None
    if proc.returncode != 0 and not proc.stdout:
        # Connection refused / unreachable — quiet at debug level
        log.debug("sslscan rc=%d for %s; stderr: %s",
                  proc.returncode, label, (proc.stderr or "").strip()[:200])
        return None
    return proc.stdout or None


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _proto_label(type_: str, version: str) -> str:
    """sslscan: <protocol type="ssl" version="3"/> → 'SSLv3';
                <protocol type="tls" version="1.2"/> → 'TLSv1.2'."""
    if type_ == "ssl":
        return f"SSLv{version}"
    return f"TLSv{version}"


def parse_sslscan_xml(xml_str: str, label: str) -> PortResult | None:
    """Parse one sslscan XML document and return a PortResult.

    Returns None on unparseable XML."""
    try:
        root = ElementTree.fromstring(xml_str)
    except ElementTree.ParseError as exc:
        log.warning("XML parse error for %s: %s", label, exc)
        return None

    test = root.find("ssltest")
    if test is None:
        return None

    port = int(test.get("port", "0"))
    pr = PortResult(port=port, reachable=True)

    # Protocol matrix ---------------------------------------------------------
    for proto in test.findall("protocol"):
        ptype = proto.get("type", "")
        pver  = proto.get("version", "")
        enabled = proto.get("enabled", "0") == "1"
        pr.protocols[_proto_label(ptype, pver)] = enabled

    # Vulnerability / handshake flags ----------------------------------------
    for hb in test.findall("heartbleed"):
        if hb.get("vulnerable", "0") == "1":
            pr.heartbleed_vulnerable.append(hb.get("sslversion", ""))

    reneg = test.find("renegotiation")
    if reneg is not None:
        pr.renegotiation_supported = reneg.get("supported", "")
        pr.renegotiation_secure    = reneg.get("secure", "")

    comp = test.find("compression")
    if comp is not None:
        pr.compression_supported = comp.get("supported", "")

    fb = test.find("fallback")
    if fb is not None:
        pr.fallback_supported = fb.get("supported", "")

    # Ciphers -----------------------------------------------------------------
    for c in test.findall("cipher"):
        try:
            pr.ciphers.append(Cipher(
                status     = c.get("status", ""),
                protocol   = _normalise_sslversion(c.get("sslversion", "")),
                name       = c.get("cipher", ""),
                bits       = int(c.get("bits", "0") or 0),
                cipher_id  = c.get("id", ""),
                strength   = c.get("strength", ""),
                curve      = c.get("curve", ""),
                ecdhe_bits = c.get("ecdhebits", ""),
                dhe_bits   = c.get("dhebits", ""),
            ))
        except ValueError:
            continue

    # Key-exchange groups -----------------------------------------------------
    for g in test.findall("group"):
        try:
            pr.groups.append(KexGroup(
                protocol = _normalise_sslversion(g.get("sslversion", "")),
                name     = g.get("name", ""),
                bits     = int(g.get("bits", "0") or 0),
                strength = g.get("strength", ""),
            ))
        except ValueError:
            continue

    # Certificate (short form is always emitted; we use the first one) -------
    cert = test.find("certificates/certificate")
    if cert is not None:
        pr.cert = _parse_certificate(cert)

    return pr


def _normalise_sslversion(s: str) -> str:
    """sslscan emits 'TLSv1.2' in the cipher XML and 'SSLv3'/'TLSv1.0' too —
    already consistent.  Pass-through, but defensively normalise stray cases."""
    if not s:
        return s
    if s.upper().startswith("TLSV"):
        return "TLSv" + s[4:]
    if s.upper().startswith("SSLV"):
        return "SSLv" + s[4:]
    return s


def _parse_certificate(elem: ElementTree.Element) -> Certificate:
    def txt(tag: str) -> str:
        e = elem.find(tag)
        return (e.text or "").strip() if e is not None and e.text else ""

    # sslscan's <signature-algorithm> element sometimes wraps the value
    # with an OpenSSL-style "Signature Algorithm:" prefix; strip it so
    # downstream consumers (and our PQ detector) see just the algorithm.
    sig_raw = txt("signature-algorithm")
    sig = re.sub(r"^\s*Signature Algorithm:\s*", "", sig_raw, flags=re.I)

    pk = elem.find("pk")
    return Certificate(
        subject              = txt("subject"),
        altnames             = txt("altnames"),
        issuer               = txt("issuer"),
        signature_algorithm  = sig,
        pk_type              = pk.get("type", "") if pk is not None else "",
        pk_bits              = pk.get("bits", "") if pk is not None else "",
        pk_curve             = pk.get("curve_name", "") if pk is not None else "",
        self_signed          = txt("self-signed"),
        not_before           = txt("not-valid-before"),
        not_after            = txt("not-valid-after"),
        expired              = txt("expired"),
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass
class Job:
    cmd: list[str]
    label: str
    source: str
    target: str          # hostname (domains) or IP (cidr)
    ip: str
    port: int
    proc_timeout: int


def plan_jobs(
    sslscan: str,
    domains: list[str],
    cidrs: list[str],
    ports: list[int],
    domain_meta: dict[str, tuple[list[str], list[str]]],
    connect_timeout: int,
    socket_timeout: int,
    iana_names: bool,
    show_times: bool,
) -> list[Job]:
    proc_timeout = socket_timeout * SUBPROC_TIMEOUT_FACTOR + 30
    jobs: list[Job] = []

    # Domain jobs: one sslscan per (ip, port) with SNI = hostname.
    for d in domains:
        _, ips = domain_meta.get(d, ([], []))
        if not ips:
            continue
        for ip in ips:
            for port in ports:
                cmd = build_sslscan_cmd(
                    sslscan,
                    target_ip=ip, port=port, sni=d,
                    connect_timeout=connect_timeout,
                    socket_timeout=socket_timeout,
                    iana_names=iana_names, show_times=show_times,
                )
                jobs.append(Job(
                    cmd=cmd, label=f"{d}@{ip}:{port}", source="domain",
                    target=d, ip=ip, port=port, proc_timeout=proc_timeout,
                ))

    # CIDR jobs: one sslscan per (ip, port), no SNI.
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            log.error("Invalid CIDR %r: %s — skipping", cidr, exc)
            continue
        hosts = list(net.hosts()) or list(net)
        log.info("Expanding %s → %d IP(s)", cidr, len(hosts))
        for ip_obj in hosts:
            ip = str(ip_obj)
            for port in ports:
                cmd = build_sslscan_cmd(
                    sslscan,
                    target_ip=ip, port=port, sni=None,
                    connect_timeout=connect_timeout,
                    socket_timeout=socket_timeout,
                    iana_names=iana_names, show_times=show_times,
                )
                jobs.append(Job(
                    cmd=cmd, label=f"{ip}:{port}", source="cidr",
                    target=ip, ip=ip, port=port, proc_timeout=proc_timeout,
                ))
    return jobs


def run_all_jobs(
    jobs: list[Job],
    workers: int,
    domain_meta: dict[str, tuple[list[str], list[str]]],
) -> dict[tuple[str, str], HostResult]:
    """Returns dict keyed by (target, ip) → HostResult."""
    results: dict[tuple[str, str], HostResult] = {}
    total = len(jobs)
    if total == 0:
        log.warning("No jobs to run")
        return results

    log.info("Queued %d sslscan job(s) across %d worker(s)", total, workers)
    milestone = max(1, total // 20)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_job = {
            ex.submit(run_sslscan, j.cmd, j.label, j.proc_timeout): j
            for j in jobs
        }
        for fut in as_completed(future_to_job):
            j = future_to_job[fut]
            completed += 1
            xml_str = fut.result()
            key = (j.target, j.ip)
            host = results.get(key)
            if host is None:
                cname, ips = ([], [])
                if j.source == "domain":
                    cname, ips = domain_meta.get(j.target, ([], []))
                host = HostResult(
                    target=j.target, ip=j.ip, source=j.source,
                    cname_chain=cname, resolved_ips=ips,
                )
                results[key] = host

            if xml_str:
                pr = parse_sslscan_xml(xml_str, j.label)
                if pr is not None:
                    pr.port = j.port  # in case XML lacked it
                    host.ports[j.port] = pr
                else:
                    host.ports[j.port] = PortResult(port=j.port, reachable=False,
                                                    error="xml-parse-failed")
            else:
                # Port not reachable or sslscan failed silently.
                host.ports[j.port] = PortResult(port=j.port, reachable=False)

            if completed % milestone == 0 or completed == total:
                log.info("Progress: %d/%d (%d%%)", completed, total,
                         100 * completed // total)

    return results


# ---------------------------------------------------------------------------
# Run metadata (for reproducibility)
# ---------------------------------------------------------------------------

@dataclass
class RunMetadata:
    """Provenance record for a single scan invocation, embedded in every
    output format so a report can be re-run later under identical conditions."""
    script: str                      # absolute path to this script
    script_version: str              # SCRIPT_VERSION constant
    command_line: list[str]          # raw sys.argv, suitable for shlex.join()
    invoked_args: dict[str, object]  # parsed argparse Namespace as dict
    started_utc: str                 # ISO-8601 UTC
    finished_utc: str = ""           # filled after orchestration completes
    duration_s: float = 0.0
    hostname: str = ""
    user: str = ""
    cwd: str = ""
    python_version: str = ""
    platform: str = ""
    sslscan_path: str = ""
    sslscan_version: str = ""
    gates: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)

    def command_string(self) -> str:
        """Shell-quoted reproduction command — safe to paste back."""
        import shlex
        return shlex.join(self.command_line) if self.command_line else ""


def _sslscan_version(sslscan_path: str) -> str:
    """Return the sslscan version banner ('d817d49-static / OpenSSL 3.5.6 …'),
    or '' if the binary can't be queried. Cheap, runs once at startup."""
    try:
        proc = subprocess.run(
            [sslscan_path, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        out = (proc.stdout + proc.stderr).strip()
        # sslscan's --version output is multi-line ASCII art; pull the lines
        # that look like the version identifier and the OpenSSL banner.
        keep = [ln.strip() for ln in out.splitlines()
                if re.search(r"static|OpenSSL|sslscan", ln, re.I)
                and not re.search(r"___|\\__|/__", ln)]
        return " / ".join(dict.fromkeys(keep))  # dedupe in order
    except (subprocess.TimeoutExpired, OSError):
        return ""


def collect_run_metadata(
    args: argparse.Namespace,
    sslscan: str,
    started_utc_iso: str,
) -> RunMetadata:
    """Build a RunMetadata record at scan start. finished_utc / duration_s
    are filled in by main() once orchestration completes."""
    import getpass, socket, sys as _sys
    gate_label = (
        next((lbl for lbl, r in STRENGTH_ORDER.items() if r == MIN_SCORE_RANK), None)
        if MIN_SCORE_RANK is not None else None
    )
    return RunMetadata(
        script=os.path.abspath(__file__),
        script_version=SCRIPT_VERSION,
        command_line=list(_sys.argv),
        invoked_args=vars(args),
        started_utc=started_utc_iso,
        hostname=socket.gethostname(),
        user=(getpass.getuser() if hasattr(getpass, "getuser") else ""),
        cwd=os.getcwd(),
        python_version=_sys.version.split()[0],
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
        sslscan_path=sslscan,
        sslscan_version=_sslscan_version(sslscan),
        gates={
            "strict_pq": STRICT_PQ,
            "min_score": gate_label,
        },
    )


# ---------------------------------------------------------------------------
# Reporting — Markdown
# ---------------------------------------------------------------------------

def _proto_sort_key(v: str) -> tuple[int, str]:
    order = {"SSLv2": 0, "SSLv3": 1, "TLSv1.0": 2, "TLSv1.1": 3,
             "TLSv1.2": 4, "TLSv1.3": 5}
    return (order.get(v, 99), v)


def _strength_badge(s: str) -> str:
    return {
        "strong":     "🟢 strong",
        "good":       "🟢 good",
        "acceptable": "🟡 acceptable",
        "medium":     "🟡 medium",
        "weak":       "🔴 weak",
        "anonymous":  "🔴 anonymous",
        "null":       "🔴 null",
    }.get((s or "").lower(), s or "—")


def render_md(
    hosts: list[HostResult],
    args: argparse.Namespace,
    scan_date: str,
    domain_meta: dict[str, tuple[list[str], list[str]]],
    domain_count: int,
    run_meta: "RunMetadata | None" = None,
) -> str:
    reachable = [h for h in hosts if h.reachable_ports()]
    flagged   = [h for h in reachable if h.has_findings()]
    unresolved = [d for d, (_c, ips) in domain_meta.items() if not ips]

    sections: list[str] = []
    sections.append(f"# TLS Configuration Audit Report\n\n_Generated: {scan_date}_\n")
    if run_meta is not None:
        sections.append(_md_section_run_metadata(run_meta))
    sections.append(_md_section_context())
    sections.append(_md_section_summary(args, scan_date, domain_count, len(args.cidr or []),
                                        reachable, flagged, unresolved))
    sections.append(_md_section_findings(reachable))
    sections.append(_md_section_details(reachable))
    return "\n".join(sections)


def _md_section_run_metadata(meta: "RunMetadata") -> str:
    """Reproducibility block. Emitted at the top so a future operator can see
    exactly when, where, and how the scan was run."""
    rows = [
        ("Started (UTC)",   meta.started_utc),
        ("Finished (UTC)",  meta.finished_utc or "(in progress)"),
        ("Duration",        f"{meta.duration_s:.1f} s" if meta.duration_s else "—"),
        ("Tool",            f"`{meta.script}` v{meta.script_version}"),
        ("sslscan",         f"`{meta.sslscan_path}` — {meta.sslscan_version or 'unknown version'}"),
        ("Python",          meta.python_version),
        ("Platform",        meta.platform),
        ("Host",            f"`{meta.hostname}`"),
        ("User",            f"`{meta.user}`"),
        ("Working dir",     f"`{meta.cwd}`"),
        ("CI gates",
         f"strict_pq={meta.gates.get('strict_pq')}, "
         f"min_score={meta.gates.get('min_score')}"),
    ]
    table = "\n".join(f"| {k} | {v} |" for k, v in rows)
    args_lines = "\n".join(
        f"- `{k}` = `{v!r}`"
        for k, v in sorted(meta.invoked_args.items())
        if v not in (None, [], "", False)
    )
    return (
        "## 0. Run Metadata\n\n"
        "_All formats embed this block so a report can be re-run identically "
        "later. The command-line is shell-escaped and safe to copy back._\n\n"
        "| Field | Value |\n|---|---|\n"
        f"{table}\n\n"
        "### Reproduction command\n\n"
        f"```sh\n{meta.command_string()}\n```\n\n"
        "### Resolved arguments (after argparse defaults)\n\n"
        f"{args_lines or '_(no non-default arguments)_'}\n\n"
    )


def _md_section_context() -> str:
    return """\
## 1. Scope and Methodology

This report is produced by `sslscan_audit.py`, which drives the
[sslscan](https://github.com/rbsec/sslscan) tool against every
(host, IP, port) tuple under audit and parses its XML output.  For each
endpoint we collect:

* Enabled / disabled SSL/TLS protocol versions
* Every accepted cipher suite (name, bits, key exchange, ECDHE curve)
* TLS 1.3 / 1.2 key-exchange groups
* Certificate chain summary (subject, altnames, issuer, signature algo,
  validity)
* Protocol-level checks: Heartbleed (CVE-2014-0160), secure renegotiation,
  TLS compression (CRIME, CVE-2012-4929), TLS_FALLBACK_SCSV support

Findings are graded against current best-practice baselines:

| Issue | Why it matters |
|---|---|
| SSLv2, SSLv3, TLS 1.0, TLS 1.1 | Mandated insecure by IETF (RFC 8996); PCI-DSS, NIST SP 800-52 Rev 2, BSI TR-02102 prohibit. |
| SHA-1 MAC cipher suites (`*_SHA`/`*-SHA`) | SHA-1 collisions are practical (SHAttered 2017, Shambles 2020). |
| RC4 ciphers | Statistical biases break confidentiality (RFC 7465 prohibits). |
| DES / 3DES (incl. `DES-CBC3-SHA`) | 56-/112-bit effective; Sweet32 birthday attack (CVE-2016-2183). |
| EXPORT ciphers | 40-/56-bit by design; FREAK / Logjam. |
| NULL / anonymous (ADH/AECDH) ciphers | No encryption / no authentication. |
| Non-PFS RSA key-exchange (TLS ≤ 1.2) | Past traffic decryptable on server key compromise. |
| CBC ciphers with TLS 1.0/1.1 | BEAST and Lucky 13 padding-oracle attacks. |
| Heartbleed (CVE-2014-0160) | Memory disclosure in vulnerable OpenSSL builds. |
| Insecure renegotiation | CVE-2009-3555 MITM data injection. |
| TLS compression | CRIME attack recovers session secrets. |

### Strength Score (sslscan's own classifier)

For every accepted cipher suite and every offered TLS 1.3 / 1.2 key-exchange
group, sslscan reports a built-in **strength** label drawn from a fixed
vocabulary that combines algorithm pedigree, key size and known attacks:

| Label | Meaning |
|---|---|
| `strong`     | Modern AEAD suite with adequate key size and PFS (e.g. AES-GCM, ChaCha20-Poly1305 with ≥ 128-bit security). |
| `good`       | Strong primitive, smaller margin or older construction. |
| `acceptable` | Mainstream but not preferred — fine for compatibility. |
| `medium`     | Marginal: works against passive attackers but discouraged in modern policy. |
| `weak`       | Known-attackable (RC4, single-DES, EXPORT, 1024-bit DH, etc.). |
| `anonymous`  | No server authentication (ADH/AECDH). |
| `null`       | No confidentiality (NULL ciphers). |

This report carries sslscan's score through unchanged, then derives a single
**overall strength** per (endpoint, port) as the *worst* label observed
across all ciphers and groups for that port — an endpoint is by definition
no stronger than its weakest negotiable primitive.  The summary table and
CSV roll this up so a fleet can be sorted by sslscan's own classifier
rather than by a re-invented grading scheme.

### Post-Quantum (PQ) Handshake Readiness

A cryptographically-relevant quantum computer (CRQC) able to run Shor's
algorithm would break every classical TLS key exchange in deployment today
(ECDH over X25519, P-256, P-384, P-521, finite-field DH).  All classical-KEX
traffic recorded today is therefore vulnerable to a **harvest-now,
decrypt-later** attack as soon as a CRQC becomes available — recordings of
captured ciphertext can be retrospectively decrypted to reveal the original
session keys and plaintext.

NIST standardised the first post-quantum key-encapsulation mechanism,
**ML-KEM** (FIPS 203, August 2024, derived from the CRYSTALS-Kyber finalist).
The IETF and IANA assigned codepoints for hybrid TLS 1.3 named groups that
combine ML-KEM with a classical curve so a handshake remains secure even if
*either* primitive turns out to be weak:

| Group | IANA ID | Status |
|---|---|---|
| `X25519MLKEM768`           | `0x11EC` | Standardised hybrid (RFC 9606, target for default deployment) |
| `SecP256r1MLKEM768`        | `0x11EB` | Standardised hybrid, NIST-curve variant |
| `MLKEM512` / `MLKEM768` / `MLKEM1024` | `0x0200`–`0x0202` | Pure ML-KEM (no classical fallback) |
| `X25519Kyber768Draft00`    | `0x6399` | Pre-standard Kyber hybrid; deployed by Chrome, Cloudflare, AWS, Google 2022–2024 |
| `SecP256r1Kyber768Draft00` | `0x639A` | Pre-standard Kyber hybrid, NIST-curve variant |

Why this matters for an audit:

* **Forward-secrecy under future quantum attack** requires at least one PQ
  KEM in the negotiated key exchange.  Endpoints lacking any PQ group offer
  no protection against harvest-now-decrypt-later.
* **Hybrid is the safe default** for the foreseeable future: a hybrid like
  `X25519MLKEM768` is at least as secure as the classical curve alone, so
  enabling it costs nothing on the security side.
* **Pure-PQ groups** (e.g. `MLKEM768` without a classical companion) commit
  the handshake to the newer primitive's security and are not recommended
  for production until the algorithm has had several more years of
  cryptanalysis.
* **Pre-standard Kyber draft codepoints** (`*Kyber768Draft00`) are being
  phased out in favour of the IANA-registered `*MLKEM768` groups; servers
  should migrate but supporting both during the transition is reasonable.

This report classifies each endpoint's PQ posture as one of:

* `hybrid`  — at least one PQ-hybrid group is offered (ideal)
* `pure-pq` — only pure-PQ groups, no classical-PQ hybrid (uncommon)
* `none`    — no PQ key-exchange support detected (action recommended)

### Post-Quantum Certificate Signatures

PQ key exchange protects the **confidentiality** of recorded traffic against
a future quantum attacker (the harvest-now-decrypt-later threat), but the
server's **certificate signature** still uses a classical algorithm (RSA,
ECDSA, EdDSA) until the CA migrates.  A quantum attacker capable of running
Shor's algorithm could forge new certificates against a classical CA key,
defeating *authentication* even when the *confidentiality* primitive is PQ.

NIST has standardised three PQ signature schemes:

| Algorithm | Standard | Notes |
|---|---|---|
| **ML-DSA** (Dilithium) | FIPS 204 (Aug 2024) | Lattice-based; primary recommendation |
| **SLH-DSA** (SPHINCS+) | FIPS 205 (Aug 2024) | Hash-based; conservative backup, large signatures |
| **FN-DSA** (Falcon) | FIPS 206 (draft) | Lattice-based with floating-point sampling |

This report flags any endpoint whose certificate is signed by one of these
algorithms (or their pre-standard names: Dilithium, SPHINCS+, Falcon).
Production CA issuance of PQ certificates is just starting; most endpoints
will show `cert_pq_signed = false` and that is currently expected.

"""


def _md_section_summary(args, scan_date, dom_count, cidr_count,
                        reachable, flagged, unresolved) -> str:
    unresolved_str = ", ".join(f"`{d}`" for d in unresolved) or "none"
    pq_hybrid  = sum(1 for h in reachable if h.pq_kex_kind() == "hybrid")
    pq_pure    = sum(1 for h in reachable if h.pq_kex_kind() == "pure-pq")
    pq_none    = sum(1 for h in reachable if h.pq_kex_kind() == "none")
    pq_signed_certs = sum(
        1 for h in reachable for p in h.reachable_ports() if p.cert.is_pq_signed()
    )
    # sslscan strength rollup across all reachable ports
    strength_rollup: dict[str, int] = {b: 0 for b in STRENGTH_BUCKETS}
    for h in reachable:
        for p in h.reachable_ports():
            label = (p.overall_strength() or "").lower()
            if label in strength_rollup:
                strength_rollup[label] += 1
    strength_summary = ", ".join(
        f"{b}: {n}" for b, n in strength_rollup.items() if n
    ) or "—"
    strict_note_parts = []
    if STRICT_PQ:
        strict_note_parts.append("strict-pq")
    if MIN_SCORE_RANK is not None:
        # Find label name for the rank
        rank_label = next(
            (lbl for lbl, r in STRENGTH_ORDER.items() if r == MIN_SCORE_RANK),
            "?",
        )
        strict_note_parts.append(f"min-score≥{rank_label}")
    strict_note = (
        f" _(gates active: {', '.join(strict_note_parts)})_"
        if strict_note_parts else ""
    )
    min_score_row_value = (
        next((lbl for lbl, r in STRENGTH_ORDER.items() if r == MIN_SCORE_RANK), "?")
        if MIN_SCORE_RANK is not None else "disabled"
    )
    lines = [
        "## 2. Scan Summary\n",
        "| Parameter | Value |",
        "|---|---|",
        f"| Scan date (UTC) | {scan_date} |",
        f"| Domain targets | {dom_count} |",
        f"| CIDR targets | {cidr_count} |",
        f"| Ports scanned | {', '.join(str(p) for p in sorted(args.ports))} |",
        f"| Parallel workers | {args.workers} |",
        f"| Strict PQ mode | {'enabled' if STRICT_PQ else 'disabled'} |",
        f"| Minimum sslscan score gate | {min_score_row_value} |",
        f"| Endpoints with at least one reachable TLS port | {len(reachable)} |",
        f"| Endpoints with findings{strict_note} | {len(flagged)} |",
        f"| sslscan overall-strength distribution (worst-of per port) | {strength_summary} |",
        f"| Endpoints with PQ hybrid key-exchange | {pq_hybrid} |",
        f"| Endpoints with pure post-quantum key-exchange | {pq_pure} |",
        f"| Endpoints with no PQ key-exchange | {pq_none} |",
        f"| Endpoint:Port pairs with PQ-signed certificates | {pq_signed_certs} |",
        f"| Domains with no DNS resolution | {unresolved_str} |",
        "",
    ]
    return "\n".join(lines) + "\n"


def _md_section_findings(reachable: list[HostResult]) -> str:
    """High-level rollups: weak protocol distribution, top weak ciphers."""
    proto_count: dict[str, int] = defaultdict(int)
    weak_cipher_count: dict[tuple[str, str], int] = defaultdict(int)  # (cipher, weakness) → n
    vuln_count = {
        "Heartbleed":             0,
        "Insecure renegotiation": 0,
        "TLS compression":        0,
        "No TLS_FALLBACK_SCSV":   0,
    }
    for h in reachable:
        for pr in h.reachable_ports():
            for p in pr.weak_protocols():
                proto_count[p] += 1
            for c, weaknesses in pr.weak_ciphers():
                for w in weaknesses:
                    weak_cipher_count[(c.name, w)] += 1
            if pr.heartbleed_vulnerable:
                vuln_count["Heartbleed"] += 1
            if pr.renegotiation_supported == "1" and pr.renegotiation_secure == "0":
                vuln_count["Insecure renegotiation"] += 1
            if pr.compression_supported == "1":
                vuln_count["TLS compression"] += 1
            if pr.fallback_supported == "0":
                vuln_count["No TLS_FALLBACK_SCSV"] += 1

    lines = ["## 3. Findings Overview\n"]

    lines.append("### Weak Protocols Enabled\n")
    if proto_count:
        lines.append("| Protocol | Endpoint:Port Count |")
        lines.append("|---|---|")
        for p in sorted(proto_count, key=_proto_sort_key):
            lines.append(f"| {p} | {proto_count[p]} |")
    else:
        lines.append("_None observed — all endpoints negotiate TLS 1.2 or 1.3 only._")
    lines.append("")

    lines.append("### Weak Cipher Suites\n")
    if weak_cipher_count:
        lines.append("| Cipher Suite | Weakness | Occurrences |")
        lines.append("|---|---|---|")
        for (name, weakness), n in sorted(weak_cipher_count.items(), key=lambda x: -x[1]):
            lines.append(f"| `{name}` | {weakness} | {n} |")
    else:
        lines.append("_No weak cipher suites observed._")
    lines.append("")

    lines.append("### Protocol-Level Vulnerabilities\n")
    lines.append("| Issue | Endpoint:Port Count |")
    lines.append("|---|---|")
    for k, v in vuln_count.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    # sslscan strength score distribution
    score_per_port: dict[str, int] = defaultdict(int)
    score_per_cipher: dict[str, int] = defaultdict(int)
    score_per_group: dict[str, int] = defaultdict(int)
    for h in reachable:
        for pr in h.reachable_ports():
            label = (pr.overall_strength() or "unknown").lower()
            score_per_port[label] += 1
            for c in pr.ciphers:
                score_per_cipher[(c.strength or "unknown").lower()] += 1
            for g in pr.groups:
                score_per_group[(g.strength or "unknown").lower()] += 1
    lines.append("### sslscan Strength Score Distribution\n")
    lines.append("Counts come straight from sslscan's own `strength` "
                 "classifier. The *Overall (per port)* column is the worst "
                 "score across every accepted cipher and offered group at "
                 "that port.\n")
    lines.append("| Score | Overall (per port) | Ciphers | KX Groups |")
    lines.append("|---|---|---|---|")
    # Order rows worst → best, then list any unknown labels last.
    ordered = [b for b in STRENGTH_BUCKETS] + sorted(
        {k for k in (score_per_port | score_per_cipher | score_per_group)
         if k not in STRENGTH_BUCKETS}
    )
    for label in ordered:
        if not (score_per_port.get(label) or score_per_cipher.get(label) or
                score_per_group.get(label)):
            continue
        lines.append(
            f"| {_strength_badge(label)} | {score_per_port.get(label, 0)} "
            f"| {score_per_cipher.get(label, 0)} | {score_per_group.get(label, 0)} |"
        )
    lines.append("")

    # Post-quantum rollup
    pq_kind_count: dict[str, int] = defaultdict(int)
    pq_group_count: dict[str, int] = defaultdict(int)
    for h in reachable:
        for pr in h.reachable_ports():
            pq_kind_count[pr.pq_kex_kind()] += 1
            for g in pr.pq_groups():
                pq_group_count[g.name] += 1
    lines.append("### Post-Quantum Key-Exchange Readiness\n")
    lines.append("| Posture | Endpoint:Port Count |")
    lines.append("|---|---|")
    for k in ("hybrid", "pure-pq", "none"):
        lines.append(f"| {k} | {pq_kind_count.get(k, 0)} |")
    lines.append("")
    if pq_group_count:
        lines.append("**PQ groups observed**\n")
        lines.append("| Group | Occurrences |")
        lines.append("|---|---|")
        for name, n in sorted(pq_group_count.items(), key=lambda x: -x[1]):
            lines.append(f"| `{name}` | {n} |")
        lines.append("")
    else:
        lines.append("_No post-quantum key-exchange groups observed across any "
                     "endpoint._\n")
    return "\n".join(lines) + "\n"


def _md_section_details(reachable: list[HostResult]) -> str:
    if not reachable:
        return "## 4. Endpoint Details\n\n_No reachable TLS endpoints._\n"
    lines = ["## 4. Endpoint Details\n"]
    # Sort: hosts with findings first, then by worst sslscan score
    # (worst → best so the most urgent endpoints surface at the top),
    # then alphabetically.
    reachable.sort(key=lambda h: (
        not h.has_findings(),
        _strength_rank(h.overall_strength()),    # low = worse, surfaces first
        h.target, h.ip,
    ))
    for h in reachable:
        heading = f"### {h.target}"
        if h.ip and h.ip != h.target:
            heading += f"  ({h.ip})"
        if h.overall_strength():
            heading += f"  — overall sslscan score: {_strength_badge(h.overall_strength())}"
        lines.append(heading + "\n")
        lines.append(f"- **Source:** {h.source}")
        if h.resolved_ips and h.source == "domain":
            lines.append(f"- **Resolved IPs:** {', '.join(h.resolved_ips)}")
        if h.cname_chain:
            lines.append(f"- **CNAME chain:** {' → '.join([h.target] + h.cname_chain)}")
        lines.append("")

        for port in sorted(h.ports):
            pr = h.ports[port]
            if not pr.reachable:
                continue

            lines.append(f"#### Port {port}\n")

            # Protocols table
            lines.append("**Protocols**\n")
            lines.append("| Protocol | Enabled |")
            lines.append("|---|---|")
            for p in sorted(pr.protocols, key=_proto_sort_key):
                en = pr.protocols[p]
                flag = "✅" if en else "—"
                weak = " ⚠️ **weak**" if en and p in WEAK_PROTOCOLS else ""
                lines.append(f"| {p} | {flag}{weak} |")
            lines.append("")

            # Vulnerabilities table
            lines.append("**Protocol-Level Checks**\n")
            lines.append("| Check | Result |")
            lines.append("|---|---|")
            hb = ", ".join(pr.heartbleed_vulnerable) if pr.heartbleed_vulnerable else "not vulnerable"
            lines.append(f"| Heartbleed | {hb} |")
            if pr.renegotiation_supported:
                rs = "secure" if pr.renegotiation_secure == "1" else \
                     ("insecure ⚠️" if pr.renegotiation_supported == "1" else "not supported")
                lines.append(f"| Renegotiation | {rs} |")
            if pr.compression_supported:
                cs = "enabled ⚠️ (CRIME)" if pr.compression_supported == "1" else "disabled"
                lines.append(f"| TLS Compression | {cs} |")
            if pr.fallback_supported:
                fb = "supported" if pr.fallback_supported == "1" else "**not supported** ⚠️"
                lines.append(f"| TLS_FALLBACK_SCSV | {fb} |")
            pq_kind = pr.pq_kex_kind()
            pq_label = {
                "hybrid":  "🟢 hybrid (PQ + classical)",
                "pure-pq": "🟡 pure post-quantum (no classical hybrid)",
                "none":    "🔴 **none** — vulnerable to harvest-now-decrypt-later"
                           + (" (flagged by --strict-pq)" if STRICT_PQ else ""),
            }[pq_kind]
            pq_names = ", ".join(f"`{g.name}`" for g in pr.pq_groups()) or "—"
            lines.append(f"| Post-Quantum KEX | {pq_label} |")
            lines.append(f"| PQ groups offered | {pq_names} |")
            cert_pq = pr.cert.is_pq_signed()
            cert_pq_label = (
                f"🟢 **{pr.cert.signature_algorithm}**"
                if cert_pq else
                f"classical (`{pr.cert.signature_algorithm or 'unknown'}`)"
            )
            lines.append(f"| Cert PQ signature | {cert_pq_label} |")
            # sslscan's own overall score for this port (worst-of cipher+group)
            overall = pr.overall_strength()
            wc = pr.worst_cipher_strength()
            wg = pr.worst_group_strength()
            lines.append(f"| sslscan score (overall worst) | {_strength_badge(overall)} |")
            if wc:
                lines.append(f"| sslscan score (worst cipher) | {_strength_badge(wc)} |")
            if wg:
                lines.append(f"| sslscan score (worst group)  | {_strength_badge(wg)} |")
            lines.append("")

            # Ciphers
            if pr.ciphers:
                lines.append("**Cipher Suites**\n")
                lines.append("| Protocol | Cipher | Bits | KX | Strength | Issues |")
                lines.append("|---|---|---|---|---|---|")
                for c in sorted(pr.ciphers, key=lambda c: (_proto_sort_key(c.protocol), -c.bits, c.name)):
                    kx_parts = []
                    if c.curve:      kx_parts.append(c.curve)
                    if c.ecdhe_bits: kx_parts.append(f"ECDHE-{c.ecdhe_bits}b")
                    if c.dhe_bits:   kx_parts.append(f"DHE-{c.dhe_bits}b")
                    kx = ", ".join(kx_parts) or "—"
                    issues = ", ".join(c.weaknesses()) or "—"
                    cell_name = f"**`{c.name}`**" if issues != "—" else f"`{c.name}`"
                    lines.append(
                        f"| {c.protocol} | {cell_name} | {c.bits} | {kx} "
                        f"| {_strength_badge(c.strength)} | {issues} |"
                    )
                lines.append("")

            # Key exchange groups
            if pr.groups:
                lines.append("**Key Exchange Groups**\n")
                lines.append("| Protocol | Group | Bits | Strength | PQ |")
                lines.append("|---|---|---|---|---|")
                for g in sorted(pr.groups, key=lambda g: (_proto_sort_key(g.protocol), -g.bits)):
                    if g.is_hybrid_pq():
                        pq_cell = "🟢 hybrid"
                    elif g.is_pq():
                        pq_cell = "🟡 pure-PQ"
                    else:
                        pq_cell = "—"
                    name_cell = f"**`{g.name}`**" if g.is_pq() else f"`{g.name}`"
                    lines.append(
                        f"| {g.protocol} | {name_cell} | {g.bits} "
                        f"| {_strength_badge(g.strength)} | {pq_cell} |"
                    )
                lines.append("")

            # Certificate
            c = pr.cert
            if c.subject or c.issuer:
                lines.append("**Certificate**\n")
                lines.append("| Field | Value |")
                lines.append("|---|---|")
                lines.append(f"| Subject | `{c.subject}` |")
                if c.altnames:
                    lines.append(f"| Subject Alt Names | `{c.altnames}` |")
                lines.append(f"| Issuer | `{c.issuer}` |")
                lines.append(f"| Signature algorithm | `{c.signature_algorithm}` |")
                pk_bits = f"{c.pk_bits}-bit" if c.pk_bits else ""
                pk_curve = f" ({c.pk_curve})" if c.pk_curve else ""
                lines.append(f"| Public key | {c.pk_type} {pk_bits}{pk_curve} |")
                lines.append(f"| Self-signed | {c.self_signed} |")
                lines.append(f"| Not before | {c.not_before} |")
                lines.append(f"| Not after  | {c.not_after} |")
                if c.expired == "true":
                    lines.append(f"| Status | **EXPIRED** ⚠️ |")
                lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Reporting — CSV
# ---------------------------------------------------------------------------

CSV_FIELDS = [
    "target", "ip", "source", "cname_chain", "port", "reachable",
    "tls_version", "cipher_suite", "bits", "kex_curve", "ecdhe_bits", "dhe_bits",
    "strength", "issues",
    "cert_subject", "cert_issuer", "cert_sig_algo", "cert_pq_signed",
    "cert_not_after", "cert_expired",
    "heartbleed", "reneg_supported", "reneg_secure",
    "compression", "fallback_scsv",
    "pq_kex_kind", "pq_groups",
    "sslscan_overall_strength", "sslscan_worst_cipher", "sslscan_worst_group",
]


def render_csv(hosts: list[HostResult],
               run_meta: "RunMetadata | None" = None) -> str:
    buf = io.StringIO()

    # Reproducibility preamble. RFC 4180 doesn't define comments, but every
    # mainstream CSV consumer (pandas, csvkit, awk) handles a leading
    # '#'-prefixed block when told to skip it (e.g. pandas read_csv(comment="#")).
    if run_meta is not None:
        buf.write("# sslscan_audit.py run metadata\n")
        for k, v in [
            ("started_utc",   run_meta.started_utc),
            ("finished_utc",  run_meta.finished_utc),
            ("duration_s",    f"{run_meta.duration_s:.3f}"),
            ("script_version", run_meta.script_version),
            ("sslscan",       run_meta.sslscan_version or "unknown"),
            ("python",        run_meta.python_version),
            ("platform",      run_meta.platform),
            ("hostname",      run_meta.hostname),
            ("user",          run_meta.user),
            ("cwd",           run_meta.cwd),
            ("gates",         json.dumps(run_meta.gates, default=str)),
            ("command",       run_meta.command_string()),
        ]:
            # Escape any embedded newlines so a single '#' line is preserved.
            v_safe = str(v).replace("\n", "\\n").replace("\r", "\\r")
            buf.write(f"# {k}: {v_safe}\n")
        buf.write("#\n")

    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()

    for h in sorted(hosts, key=lambda h: (h.target, h.ip)):
        for port in sorted(h.ports):
            pr = h.ports[port]
            pq_kind = pr.pq_kex_kind()
            pq_names = "|".join(g.name for g in pr.pq_groups())
            score_overall = pr.overall_strength()
            score_cipher  = pr.worst_cipher_strength()
            score_group   = pr.worst_group_strength()
            common = {
                "target": h.target, "ip": h.ip, "source": h.source,
                "cname_chain": " -> ".join(h.cname_chain),
                "port": port, "reachable": pr.reachable,
                "cert_subject": pr.cert.subject, "cert_issuer": pr.cert.issuer,
                "cert_sig_algo": pr.cert.signature_algorithm,
                "cert_pq_signed": pr.cert.is_pq_signed(),
                "cert_not_after": pr.cert.not_after, "cert_expired": pr.cert.expired,
                "heartbleed": ",".join(pr.heartbleed_vulnerable),
                "reneg_supported": pr.renegotiation_supported,
                "reneg_secure": pr.renegotiation_secure,
                "compression": pr.compression_supported,
                "fallback_scsv": pr.fallback_supported,
                "pq_kex_kind": pq_kind, "pq_groups": pq_names,
                "sslscan_overall_strength": score_overall,
                "sslscan_worst_cipher": score_cipher,
                "sslscan_worst_group": score_group,
            }
            if not pr.ciphers:
                # Still emit one row so unreachable / no-TLS ports show up.
                w.writerow({**common,
                    "tls_version": "", "cipher_suite": "", "bits": "",
                    "kex_curve": "", "ecdhe_bits": "", "dhe_bits": "",
                    "strength": "", "issues": "",
                })
                continue
            for c in pr.ciphers:
                w.writerow({**common,
                    "tls_version": c.protocol, "cipher_suite": c.name,
                    "bits": c.bits, "kex_curve": c.curve,
                    "ecdhe_bits": c.ecdhe_bits, "dhe_bits": c.dhe_bits,
                    "strength": c.strength,
                    "issues": "|".join(c.weaknesses()),
                })
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Reporting — JSON
# ---------------------------------------------------------------------------

def render_json(
    hosts: list[HostResult],
    args: argparse.Namespace,
    scan_date: str,
    domain_meta: dict[str, tuple[list[str], list[str]]],
    run_meta: "RunMetadata | None" = None,
) -> str:
    # Strength-score rollup at the fleet level
    score_rollup: dict[str, int] = {b: 0 for b in STRENGTH_BUCKETS}
    for h in hosts:
        for p in h.reachable_ports():
            label = (p.overall_strength() or "").lower()
            if label in score_rollup:
                score_rollup[label] += 1

    doc = {
        "meta": {
            "scan_date": scan_date,
            "ports_scanned": sorted(args.ports),
            "total_endpoints": len(hosts),
            "endpoints_reachable": sum(1 for h in hosts if h.reachable_ports()),
            "endpoints_with_findings": sum(1 for h in hosts if h.has_findings()),
            "endpoints_pq_hybrid":  sum(1 for h in hosts if h.pq_kex_kind() == "hybrid"),
            "endpoints_pq_pure":    sum(1 for h in hosts if h.pq_kex_kind() == "pure-pq"),
            "endpoints_pq_none":    sum(1 for h in hosts if h.reachable_ports()
                                        and h.pq_kex_kind() == "none"),
            "sslscan_score_rollup": score_rollup,
            "unresolvable_domains": [d for d, (_c, ips) in domain_meta.items() if not ips],
            # Embedded run-metadata: provenance for reproducibility.
            # Consumers wanting just the scan results can ignore meta.run.
            "run": (run_meta.as_dict() if run_meta is not None else None),
        },
        "endpoints": [],
    }
    for h in sorted(hosts, key=lambda h: (h.target, h.ip)):
        host_doc = {
            "target": h.target,
            "ip": h.ip,
            "source": h.source,
            "cname_chain": h.cname_chain,
            "resolved_ips": h.resolved_ips,
            "has_findings": h.has_findings(),
            "pq_kex_kind": h.pq_kex_kind(),
            "sslscan_overall_strength": h.overall_strength(),
            "ports": [],
        }
        for port in sorted(h.ports):
            pr = h.ports[port]
            host_doc["ports"].append({
                "port": port,
                "reachable": pr.reachable,
                "protocols": pr.protocols,
                "ciphers": [
                    {**asdict(c), "issues": c.weaknesses()} for c in pr.ciphers
                ],
                "groups": [
                    {**asdict(g), "pq": g.is_pq(), "pq_hybrid": g.is_hybrid_pq()}
                    for g in pr.groups
                ],
                "post_quantum": {
                    "kind": pr.pq_kex_kind(),
                    "supported": pr.pq_kex_supported(),
                    "groups": [g.name for g in pr.pq_groups()],
                    "cert_pq_signed": pr.cert.is_pq_signed(),
                    "cert_signature_algorithm": pr.cert.signature_algorithm,
                },
                "sslscan_score": {
                    "overall":      pr.overall_strength(),
                    "worst_cipher": pr.worst_cipher_strength(),
                    "worst_group":  pr.worst_group_strength(),
                    "cipher_distribution": pr.cipher_strength_distribution(),
                },
                "certificate": {**asdict(pr.cert), "pq_signed": pr.cert.is_pq_signed()},
                "heartbleed_vulnerable": pr.heartbleed_vulnerable,
                "renegotiation_supported": pr.renegotiation_supported,
                "renegotiation_secure":    pr.renegotiation_secure,
                "compression_supported":   pr.compression_supported,
                "fallback_scsv_supported": pr.fallback_supported,
                "error": pr.error,
            })
        doc["endpoints"].append(host_doc)
    return json.dumps(doc, indent=2)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class ColorFormatter(logging.Formatter):
    _RESET = "\033[0m"
    _DIM   = "\033[2m"
    _LEVEL = {
        logging.DEBUG:    "\033[2;37m",
        logging.INFO:     "\033[36m",
        logging.WARNING:  "\033[33m",
        logging.ERROR:    "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }
    _PATTERNS = [
        (re.compile(r"(\d+/\d+)"), "\033[1;37m"),
        (re.compile(r"(\d+\s?%)"), "\033[92m"),
        (re.compile(r"(timeout|failed|truncated)", re.I), "\033[91m"),
    ]

    def __init__(self, use_colour: bool = True):
        super().__init__(datefmt="%H:%M:%S")
        self._use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, self.datefmt)
        msg = record.getMessage()
        if not self._use_colour:
            return f"{ts} {record.levelname}: {msg}"
        level_col = self._LEVEL.get(record.levelno, "")
        badge = f"{level_col}{record.levelname}{self._RESET}"
        ts_str = f"{self._DIM}{ts}{self._RESET}"
        for pat, col in self._PATTERNS:
            msg = pat.sub(lambda m: f"{col}{m.group(1)}{self._RESET}", msg)
        if record.levelno >= logging.WARNING:
            msg = f"{level_col}{msg}{self._RESET}"
        return f"{ts_str} {badge}: {msg}"


# ---------------------------------------------------------------------------
# Reporting — HTML
# ---------------------------------------------------------------------------

import html as _html

HTML_CSS = """
:root {
  --bg: #0f1419;
  --bg-2: #161b22;
  --bg-3: #1c2230;
  --fg: #e6edf3;
  --fg-dim: #8b949e;
  --border: #30363d;
  --accent: #58a6ff;
  --good: #3fb950;
  --mid: #d29922;
  --bad: #f85149;
  --mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --bg-2: #f6f8fa;
    --bg-3: #eef2f7;
    --fg: #1f2328;
    --fg-dim: #57606a;
    --border: #d0d7de;
    --accent: #0969da;
    --good: #1f883d;
    --mid: #9a6700;
    --bad: #cf222e;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--fg);
  line-height: 1.5;
}
.wrap { max-width: 1200px; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }
h1, h2, h3, h4 { line-height: 1.25; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; }
h2 { font-size: 1.4rem; margin: 2rem 0 .5rem; padding-bottom: .3rem;
     border-bottom: 1px solid var(--border); }
h3 { font-size: 1.15rem; margin: 0; }
h4 { font-size: 1rem; margin: .75rem 0 .25rem; color: var(--fg-dim); }
.subtitle { color: var(--fg-dim); margin: 0 0 1rem; font-size: .92rem; }

.toolbar {
  position: sticky; top: 0; z-index: 20;
  background: var(--bg); padding: .5rem 0 .75rem;
  border-bottom: 1px solid var(--border); margin-bottom: 1rem;
  display: flex; gap: .5rem; flex-wrap: wrap; align-items: center;
}
.toolbar button {
  background: var(--bg-2); color: var(--fg); border: 1px solid var(--border);
  padding: .35rem .8rem; border-radius: 6px; cursor: pointer;
  font-size: .9rem; font-family: inherit;
}
.toolbar button:hover { background: var(--bg-3); border-color: var(--accent); }
.toolbar button.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.toolbar .filter {
  flex: 1; min-width: 220px;
  background: var(--bg-2); color: var(--fg); border: 1px solid var(--border);
  padding: .35rem .65rem; border-radius: 6px; font-family: inherit;
}
.toolbar label { display: flex; align-items: center; gap: .35rem;
  font-size: .88rem; color: var(--fg-dim); }

table {
  width: 100%; border-collapse: collapse;
  background: var(--bg-2); border: 1px solid var(--border);
  border-radius: 6px; overflow: hidden; margin: .5rem 0 1rem;
  font-size: .92rem;
}
th, td { padding: .45rem .65rem; text-align: left;
  border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: var(--bg-3); font-weight: 600; color: var(--fg-dim);
  font-size: .82rem; text-transform: uppercase; letter-spacing: .02em; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg-3); }
code { font-family: var(--mono); font-size: .87rem;
  background: var(--bg-3); padding: 1px 5px; border-radius: 3px; }

.badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-size: .78rem; font-weight: 600; white-space: nowrap;
  border: 1px solid var(--border); background: var(--bg-3); }
.badge.good { color: var(--good); border-color: var(--good); }
.badge.mid  { color: var(--mid);  border-color: var(--mid);  }
.badge.bad  { color: var(--bad);  border-color: var(--bad);  }
.badge.muted { color: var(--fg-dim); }
.dot { display: inline-block; width: .55rem; height: .55rem;
  border-radius: 50%; margin-right: .35rem; vertical-align: 1px; }
.dot.good { background: var(--good); }
.dot.mid  { background: var(--mid);  }
.dot.bad  { background: var(--bad);  }
.dot.muted { background: var(--fg-dim); }

details {
  background: var(--bg-2); border: 1px solid var(--border);
  border-radius: 8px; margin: .5rem 0; overflow: hidden;
}
details > summary {
  cursor: pointer; padding: .65rem .9rem; user-select: none;
  display: flex; align-items: center; gap: .65rem; flex-wrap: wrap;
  background: var(--bg-2);
  list-style: none;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: "▸"; color: var(--fg-dim); transition: transform .15s ease;
  display: inline-block; width: 1em;
}
details[open] > summary::before { transform: rotate(90deg); }
details > summary:hover { background: var(--bg-3); }
details .body { padding: .5rem .9rem 1rem; }

details.endpoint { border-color: var(--border); }
details.endpoint.flagged { border-color: var(--bad); }
details.endpoint.flagged > summary {
  background: linear-gradient(to right, color-mix(in srgb, var(--bad) 10%, var(--bg-2)) 0%, var(--bg-2) 50%);
}
details.port { background: var(--bg-3); }

.meta-line { color: var(--fg-dim); font-size: .85rem;
  margin-left: .25rem; }
.endpoint-title { font-weight: 600; }
.endpoint-sub { color: var(--fg-dim); font-size: .85rem; }
.tag-strip { display: flex; gap: .35rem; flex-wrap: wrap;
  margin-left: auto; }

.context, .summary, .findings, .details-section { margin-bottom: .5rem; }
.context p, .findings p { margin: .5rem 0; }
.context li { margin: .25rem 0; }

.no-results { color: var(--fg-dim); font-style: italic; padding: .75rem 0; }
.footer { color: var(--fg-dim); font-size: .82rem;
  border-top: 1px solid var(--border); margin-top: 2rem; padding-top: .75rem; }
"""

HTML_JS = """
(function () {
  const allDetails = () => document.querySelectorAll("details.collapsible");
  const setAll = (open) => allDetails().forEach(d => { d.open = open; });

  document.getElementById("expand-all").addEventListener("click", () => setAll(true));
  document.getElementById("collapse-all").addEventListener("click", () => setAll(false));
  document.getElementById("flagged-only").addEventListener("change", (e) => {
    const flaggedOnly = e.target.checked;
    document.querySelectorAll("details.endpoint").forEach(d => {
      const flagged = d.classList.contains("flagged");
      d.style.display = (flaggedOnly && !flagged) ? "none" : "";
    });
  });

  const filter = document.getElementById("filter");
  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    document.querySelectorAll("details.endpoint").forEach(d => {
      const hay = d.dataset.search || "";
      const hide = q && !hay.includes(q);
      d.style.display = hide ? "none" : "";
      if (q) d.open = true;
    });
  });
})();
"""


def _html_escape(s: str) -> str:
    return _html.escape(s, quote=True) if s else ""


def _badge_class(strength: str) -> str:
    """Map sslscan strength label → CSS badge class."""
    s = (strength or "").lower()
    if s in ("strong", "good"):       return "good"
    if s in ("acceptable", "medium"): return "mid"
    if s in ("weak", "anonymous", "null"): return "bad"
    return "muted"


def _badge_html(strength: str, label: str | None = None) -> str:
    text = label if label is not None else strength
    if not text:
        return '<span class="badge muted">—</span>'
    cls = _badge_class(strength)
    return f'<span class="badge {cls}">{_html_escape(text)}</span>'


def _pq_kind_badge(kind: str) -> str:
    if kind == "hybrid":
        return '<span class="badge good">PQ hybrid</span>'
    if kind == "pure-pq":
        return '<span class="badge mid">pure PQ</span>'
    return '<span class="badge bad">no PQ</span>'


def render_html(
    hosts: list[HostResult],
    args: argparse.Namespace,
    scan_date: str,
    domain_meta: dict[str, tuple[list[str], list[str]]],
    domain_count: int,
    run_meta: "RunMetadata | None" = None,
) -> str:
    reachable = [h for h in hosts if h.reachable_ports()]
    flagged   = [h for h in reachable if h.has_findings()]
    unresolved = [d for d, (_c, ips) in domain_meta.items() if not ips]

    # Embed run-metadata as a top-of-file comment too, so even with JS
    # disabled / the details section collapsed, `grep` and `view-source`
    # can recover the exact provenance.
    archival_comment = ""
    if run_meta is not None:
        meta_blob = json.dumps(run_meta.as_dict(), indent=2, default=str)
        archival_comment = (
            "<!-- sslscan_audit run metadata (machine-readable):\n"
            + meta_blob.replace("--", "-\u200b-")   # neutralise '--' inside comments
            + "\n-->\n"
        )

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS Configuration Audit Report — {_html_escape(scan_date)}</title>
<style>{HTML_CSS}</style>
</head>
<body>
{archival_comment}<div class="wrap">
<h1>TLS Configuration Audit Report</h1>
<p class="subtitle">Generated {_html_escape(scan_date)} ·
  {len(reachable)} reachable endpoint(s), {len(flagged)} with findings ·
  produced by <code>sslscan_audit.py</code>
</p>

<div class="toolbar" role="toolbar" aria-label="Report controls">
  <button id="expand-all" class="primary" type="button">Expand all</button>
  <button id="collapse-all" type="button">Collapse all</button>
  <input id="filter" class="filter" type="search"
         placeholder="Filter endpoints (hostname, IP, cipher, CN…)">
  <label><input id="flagged-only" type="checkbox"> Flagged only</label>
</div>
""")

    if run_meta is not None:
        parts.append(_html_section_run_metadata(run_meta))
    parts.append(_html_section_context())
    parts.append(_html_section_summary(args, scan_date, domain_count,
                                       len(args.cidr or []), reachable,
                                       flagged, unresolved))
    parts.append(_html_section_findings(reachable))
    parts.append(_html_section_details(reachable))

    parts.append(f"""
<div class="footer">
  Built from sslscan XML output. Strength labels (<code>strong</code>,
  <code>good</code>, <code>acceptable</code>, <code>medium</code>,
  <code>weak</code>, <code>anonymous</code>, <code>null</code>) come from
  sslscan's own classifier; PQ KEX and PQ certificate-signature detection,
  weakness tagging, and exit-code gating are applied by sslscan_audit.py.
</div>

<script>{HTML_JS}</script>
</div>
</body>
</html>
""")
    return "".join(parts)


def _html_section_run_metadata(meta: "RunMetadata") -> str:
    """Reproducibility section — collapsed by default to keep findings front
    and center, but always present in the document."""
    rows = [
        ("Started (UTC)",  _html_escape(meta.started_utc)),
        ("Finished (UTC)", _html_escape(meta.finished_utc or "(in progress)")),
        ("Duration",       f"{meta.duration_s:.1f} s" if meta.duration_s else "—"),
        ("Tool",           f"<code>{_html_escape(meta.script)}</code> "
                           f"v{_html_escape(meta.script_version)}"),
        ("sslscan",        f"<code>{_html_escape(meta.sslscan_path)}</code> — "
                           f"{_html_escape(meta.sslscan_version) or 'unknown version'}"),
        ("Python",         _html_escape(meta.python_version)),
        ("Platform",       _html_escape(meta.platform)),
        ("Host",           f"<code>{_html_escape(meta.hostname)}</code>"),
        ("User",           f"<code>{_html_escape(meta.user)}</code>"),
        ("Working dir",    f"<code>{_html_escape(meta.cwd)}</code>"),
        ("CI gates",
         f"strict_pq=<code>{_html_escape(str(meta.gates.get('strict_pq')))}</code>, "
         f"min_score=<code>{_html_escape(str(meta.gates.get('min_score')))}</code>"),
    ]
    table = "".join(
        f"<tr><th>{_html_escape(k)}</th><td>{v}</td></tr>" for k, v in rows
    )
    args_items = "".join(
        f"<tr><th><code>{_html_escape(k)}</code></th>"
        f"<td><code>{_html_escape(repr(v))}</code></td></tr>"
        for k, v in sorted(meta.invoked_args.items())
        if v not in (None, [], "", False)
    ) or '<tr><td colspan="2" class="no-results">(no non-default arguments)</td></tr>'
    return f"""
<details class="collapsible run-meta">
  <summary><h3>0. Run Metadata <span class="endpoint-sub">(for reproducibility)</span></h3></summary>
  <div class="body">
    <p>All formats embed this block so a report can be re-run identically
       later. The command-line below is shell-escaped and safe to copy back.</p>
    <table><tbody>{table}</tbody></table>
    <h4>Reproduction command</h4>
    <pre><code>{_html_escape(meta.command_string())}</code></pre>
    <h4>Resolved arguments (after argparse defaults)</h4>
    <table><tbody>{args_items}</tbody></table>
  </div>
</details>
"""


def _html_section_context() -> str:
    return """
<details class="collapsible context">
  <summary><h3>1. Scope &amp; Methodology</h3></summary>
  <div class="body">
    <p>This report drives <code>sslscan</code> against every
    (host&nbsp;|&nbsp;IP, port) under audit and parses its XML output.
    For each endpoint it collects:</p>
    <ul>
      <li>Enabled / disabled SSL/TLS protocol versions</li>
      <li>Every accepted cipher suite with bits, key exchange, ECDHE curve</li>
      <li>TLS 1.3 / 1.2 key-exchange groups including post-quantum groups
          (X25519MLKEM768, X25519Kyber768Draft00, …)</li>
      <li>Certificate details and post-quantum signature detection
          (ML-DSA, SLH-DSA, Falcon, Dilithium, SPHINCS+, …)</li>
      <li>Protocol-level checks: Heartbleed, secure renegotiation,
          TLS compression (CRIME), TLS_FALLBACK_SCSV</li>
      <li>sslscan's own per-cipher and per-group <em>strength</em> score,
          rolled up to a worst-of-port and worst-of-host value</li>
    </ul>
    <p><strong>Strength labels</strong> (worst → best):
      <span class="badge bad">null</span>
      <span class="badge bad">anonymous</span>
      <span class="badge bad">weak</span>
      <span class="badge mid">medium</span>
      <span class="badge mid">acceptable</span>
      <span class="badge good">good</span>
      <span class="badge good">strong</span>
    </p>
    <p><strong>PQ posture</strong>:
      <span class="badge good">PQ hybrid</span> (PQ + classical curve — ideal),
      <span class="badge mid">pure PQ</span> (PQ only — uncommon),
      <span class="badge bad">no PQ</span> (vulnerable to harvest-now-decrypt-later).
    </p>
  </div>
</details>
"""


def _html_section_summary(args, scan_date, dom_count, cidr_count,
                          reachable, flagged, unresolved) -> str:
    pq_hybrid = sum(1 for h in reachable if h.pq_kex_kind() == "hybrid")
    pq_pure   = sum(1 for h in reachable if h.pq_kex_kind() == "pure-pq")
    pq_none   = sum(1 for h in reachable if h.pq_kex_kind() == "none")
    pq_signed_certs = sum(
        1 for h in reachable for p in h.reachable_ports() if p.cert.is_pq_signed()
    )
    score_rollup: dict[str, int] = {b: 0 for b in STRENGTH_BUCKETS}
    for h in reachable:
        for p in h.reachable_ports():
            label = (p.overall_strength() or "").lower()
            if label in score_rollup:
                score_rollup[label] += 1
    strength_pills = " ".join(
        f'<span class="badge {_badge_class(b)}">{b}: {n}</span>'
        for b, n in score_rollup.items() if n
    ) or '<span class="badge muted">—</span>'

    gates: list[str] = []
    if STRICT_PQ:
        gates.append("strict-pq")
    if MIN_SCORE_RANK is not None:
        lbl = next((k for k, r in STRENGTH_ORDER.items() if r == MIN_SCORE_RANK), "?")
        gates.append(f"min-score≥{lbl}")
    gates_str = ", ".join(gates) if gates else "none"
    unresolved_str = ", ".join(f"<code>{_html_escape(d)}</code>" for d in unresolved) or "none"

    rows = [
        ("Scan date (UTC)", _html_escape(scan_date)),
        ("Domain targets", str(dom_count)),
        ("CIDR targets", str(cidr_count)),
        ("Ports scanned", ", ".join(str(p) for p in sorted(args.ports))),
        ("Parallel workers", str(args.workers)),
        ("CI gates active", gates_str),
        ("Endpoints reachable", str(len(reachable))),
        ("Endpoints with findings", str(len(flagged))),
        ("Overall-strength distribution", strength_pills),
        ("PQ hybrid endpoints", str(pq_hybrid)),
        ("Pure-PQ endpoints", str(pq_pure)),
        ("No-PQ endpoints", str(pq_none)),
        ("PQ-signed certificates", str(pq_signed_certs)),
        ("Domains with no DNS resolution", unresolved_str),
    ]
    body = "\n".join(
        f"<tr><th>{_html_escape(k)}</th><td>{v}</td></tr>" for k, v in rows
    )
    return f"""
<details class="collapsible summary" open>
  <summary><h3>2. Scan Summary</h3></summary>
  <div class="body">
    <table><tbody>{body}</tbody></table>
  </div>
</details>
"""


def _html_section_findings(reachable: list[HostResult]) -> str:
    proto_count: dict[str, int] = defaultdict(int)
    weak_cipher_count: dict[tuple[str, str], int] = defaultdict(int)
    vuln_count = {"Heartbleed": 0, "Insecure renegotiation": 0,
                  "TLS compression": 0, "No TLS_FALLBACK_SCSV": 0}
    score_per_port: dict[str, int] = defaultdict(int)
    score_per_cipher: dict[str, int] = defaultdict(int)
    score_per_group: dict[str, int] = defaultdict(int)
    pq_kind_count: dict[str, int] = defaultdict(int)
    pq_group_count: dict[str, int] = defaultdict(int)
    for h in reachable:
        for pr in h.reachable_ports():
            for p in pr.weak_protocols():
                proto_count[p] += 1
            for c, weaknesses in pr.weak_ciphers():
                for w in weaknesses:
                    weak_cipher_count[(c.name, w)] += 1
            if pr.heartbleed_vulnerable:
                vuln_count["Heartbleed"] += 1
            if pr.renegotiation_supported == "1" and pr.renegotiation_secure == "0":
                vuln_count["Insecure renegotiation"] += 1
            if pr.compression_supported == "1":
                vuln_count["TLS compression"] += 1
            if pr.fallback_supported == "0":
                vuln_count["No TLS_FALLBACK_SCSV"] += 1
            score_per_port[(pr.overall_strength() or "unknown").lower()] += 1
            for c in pr.ciphers:
                score_per_cipher[(c.strength or "unknown").lower()] += 1
            for g in pr.groups:
                score_per_group[(g.strength or "unknown").lower()] += 1
            pq_kind_count[pr.pq_kex_kind()] += 1
            for g in pr.pq_groups():
                pq_group_count[g.name] += 1

    def _table(headers, rows, empty_msg):
        if not rows:
            return f'<p class="no-results">{empty_msg}</p>'
        th = "".join(f"<th>{_html_escape(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
            for row in rows
        )
        return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"

    weak_proto_rows = [
        (p, str(proto_count[p]))
        for p in sorted(proto_count, key=_proto_sort_key)
    ]
    weak_cipher_rows = [
        (f"<code>{_html_escape(name)}</code>", _html_escape(w), str(n))
        for (name, w), n in sorted(weak_cipher_count.items(), key=lambda x: -x[1])
    ]
    vuln_rows = [(k, str(v)) for k, v in vuln_count.items()]
    score_rows = []
    ordered = list(STRENGTH_BUCKETS) + sorted(
        {k for k in (score_per_port | score_per_cipher | score_per_group)
         if k not in STRENGTH_BUCKETS}
    )
    for label in ordered:
        if not (score_per_port.get(label) or score_per_cipher.get(label) or
                score_per_group.get(label)):
            continue
        score_rows.append((
            _badge_html(label),
            str(score_per_port.get(label, 0)),
            str(score_per_cipher.get(label, 0)),
            str(score_per_group.get(label, 0)),
        ))
    pq_rows = [
        (_pq_kind_badge(k), str(pq_kind_count.get(k, 0)))
        for k in ("hybrid", "pure-pq", "none")
    ]
    pq_group_rows = [
        (f"<code>{_html_escape(n)}</code>", str(c))
        for n, c in sorted(pq_group_count.items(), key=lambda x: -x[1])
    ]

    return f"""
<details class="collapsible findings" open>
  <summary><h3>3. Findings Overview</h3></summary>
  <div class="body">
    <h4>Weak protocols enabled</h4>
    {_table(["Protocol", "Endpoint:Port count"], weak_proto_rows,
            "No weak protocols observed.")}
    <h4>Weak cipher suites</h4>
    {_table(["Cipher", "Weakness", "Occurrences"], weak_cipher_rows,
            "No weak cipher suites observed.")}
    <h4>Protocol-level vulnerabilities</h4>
    {_table(["Issue", "Endpoint:Port count"], vuln_rows, "")}
    <h4>sslscan strength score distribution</h4>
    {_table(["Score", "Overall (per port)", "Ciphers", "KX Groups"], score_rows,
            "No strength data collected.")}
    <h4>Post-quantum key-exchange posture</h4>
    {_table(["Posture", "Endpoint:Port count"], pq_rows, "")}
    {"<h4>PQ groups observed</h4>" + _table(["Group", "Occurrences"], pq_group_rows, "") if pq_group_rows else ""}
  </div>
</details>
"""


def _html_section_details(reachable: list[HostResult]) -> str:
    if not reachable:
        return """
<details class="collapsible details-section" open>
  <summary><h3>4. Endpoint Details</h3></summary>
  <div class="body"><p class="no-results">No reachable TLS endpoints.</p></div>
</details>
"""

    reachable.sort(key=lambda h: (
        not h.has_findings(),
        _strength_rank(h.overall_strength()),
        h.target, h.ip,
    ))

    cards = "".join(_html_endpoint_card(h) for h in reachable)
    return f"""
<details class="collapsible details-section" open>
  <summary><h3>4. Endpoint Details ({len(reachable)} endpoints)</h3></summary>
  <div class="body">{cards}</div>
</details>
"""


def _html_endpoint_card(h: HostResult) -> str:
    flagged = h.has_findings()
    cls = "endpoint collapsible" + (" flagged" if flagged else "")
    overall = h.overall_strength()
    badges = [_badge_html(overall)] if overall else []
    badges.append(_pq_kind_badge(h.pq_kex_kind()))
    if flagged:
        badges.append('<span class="badge bad">findings</span>')
    badges_html = '<span class="tag-strip">' + " ".join(badges) + '</span>'

    # Build a lowercase haystack for the filter input.
    search_terms = [h.target, h.ip] + h.cname_chain + h.resolved_ips
    for pr in h.reachable_ports():
        search_terms.append(str(pr.port))
        search_terms.append(pr.cert.subject)
        search_terms.append(pr.cert.altnames)
        search_terms.append(pr.cert.issuer)
        search_terms.extend(c.name for c in pr.ciphers)
        search_terms.extend(g.name for g in pr.groups)
    haystack = " ".join(t.lower() for t in search_terms if t)

    title = _html_escape(h.target)
    sub = f"({_html_escape(h.ip)})" if h.ip and h.ip != h.target else ""
    meta_bits = []
    if h.source == "domain" and h.resolved_ips:
        meta_bits.append("resolved: " + ", ".join(_html_escape(ip) for ip in h.resolved_ips))
    if h.cname_chain:
        meta_bits.append("CNAME: " + " → ".join(_html_escape(c) for c in [h.target] + h.cname_chain))
    meta = ("<div class=\"endpoint-sub\">" + " · ".join(meta_bits) + "</div>") if meta_bits else ""

    port_blocks = "".join(_html_port_block(pr) for port, pr in sorted(h.ports.items())
                          if pr.reachable)

    return f"""
<details class="{cls}" data-search="{_html_escape(haystack)}">
  <summary>
    <span class="endpoint-title">{title}</span>
    <span class="endpoint-sub">{sub}</span>
    {badges_html}
  </summary>
  <div class="body">
    {meta}
    {port_blocks}
  </div>
</details>
"""


def _html_port_block(pr: PortResult) -> str:
    # ----- Checks table -----
    rows: list[tuple[str, str]] = []
    rows.append(("Heartbleed",
                 ", ".join(pr.heartbleed_vulnerable) if pr.heartbleed_vulnerable
                 else '<span class="badge good">not vulnerable</span>'))
    if pr.renegotiation_supported:
        if pr.renegotiation_secure == "1":
            v = '<span class="badge good">secure</span>'
        elif pr.renegotiation_supported == "1":
            v = '<span class="badge bad">insecure</span>'
        else:
            v = '<span class="badge muted">not supported</span>'
        rows.append(("Renegotiation", v))
    if pr.compression_supported:
        v = ('<span class="badge bad">enabled (CRIME)</span>'
             if pr.compression_supported == "1"
             else '<span class="badge good">disabled</span>')
        rows.append(("TLS Compression", v))
    if pr.fallback_supported:
        v = ('<span class="badge good">supported</span>'
             if pr.fallback_supported == "1"
             else '<span class="badge bad">not supported</span>')
        rows.append(("TLS_FALLBACK_SCSV", v))
    rows.append(("Post-Quantum KEX", _pq_kind_badge(pr.pq_kex_kind())))
    if pr.pq_groups():
        rows.append(("PQ groups offered",
                     ", ".join(f"<code>{_html_escape(g.name)}</code>"
                               for g in pr.pq_groups())))
    cert_pq_html = (
        f'<span class="badge good">{_html_escape(pr.cert.signature_algorithm)}</span>'
        if pr.cert.is_pq_signed()
        else f'<span class="badge muted">classical</span> '
             f'<code>{_html_escape(pr.cert.signature_algorithm or "unknown")}</code>'
    )
    rows.append(("Cert PQ signature", cert_pq_html))
    rows.append(("sslscan overall (worst-of)", _badge_html(pr.overall_strength())))
    if pr.worst_cipher_strength():
        rows.append(("sslscan worst cipher", _badge_html(pr.worst_cipher_strength())))
    if pr.worst_group_strength():
        rows.append(("sslscan worst group", _badge_html(pr.worst_group_strength())))
    checks_table = "<table><tbody>" + "".join(
        f"<tr><th>{_html_escape(k)}</th><td>{v}</td></tr>" for k, v in rows
    ) + "</tbody></table>"

    # ----- Protocols -----
    proto_rows = []
    for p in sorted(pr.protocols, key=_proto_sort_key):
        enabled = pr.protocols[p]
        flag = (
            '<span class="badge bad">enabled (weak)</span>' if enabled and p in WEAK_PROTOCOLS
            else '<span class="badge good">enabled</span>' if enabled
            else '<span class="badge muted">—</span>'
        )
        proto_rows.append((p, flag))
    proto_table = "<table><thead><tr><th>Protocol</th><th>State</th></tr></thead><tbody>" + "".join(
        f"<tr><td>{_html_escape(p)}</td><td>{f}</td></tr>" for p, f in proto_rows
    ) + "</tbody></table>"

    # ----- Ciphers -----
    cipher_rows = ""
    for c in sorted(pr.ciphers, key=lambda c: (_proto_sort_key(c.protocol), -c.bits, c.name)):
        kx_parts = []
        if c.curve: kx_parts.append(c.curve)
        if c.ecdhe_bits: kx_parts.append(f"ECDHE-{c.ecdhe_bits}b")
        if c.dhe_bits:   kx_parts.append(f"DHE-{c.dhe_bits}b")
        kx = ", ".join(kx_parts) or "—"
        issues = ", ".join(c.weaknesses())
        issues_html = (f'<span class="badge bad">{_html_escape(issues)}</span>'
                       if issues else '<span class="badge muted">—</span>')
        cipher_rows += (
            f"<tr><td>{_html_escape(c.protocol)}</td>"
            f"<td><code>{_html_escape(c.name)}</code></td>"
            f"<td>{c.bits}</td><td>{_html_escape(kx)}</td>"
            f"<td>{_badge_html(c.strength)}</td>"
            f"<td>{issues_html}</td></tr>"
        )
    cipher_table = (
        "<table><thead><tr><th>Protocol</th><th>Cipher</th><th>Bits</th>"
        "<th>KX</th><th>Strength</th><th>Issues</th></tr></thead>"
        f"<tbody>{cipher_rows}</tbody></table>"
        if cipher_rows else
        '<p class="no-results">No accepted cipher suites.</p>'
    )

    # ----- Groups -----
    group_rows = ""
    for g in sorted(pr.groups, key=lambda g: (_proto_sort_key(g.protocol), -g.bits)):
        if g.is_hybrid_pq(): pq_cell = '<span class="badge good">hybrid</span>'
        elif g.is_pq():      pq_cell = '<span class="badge mid">pure-PQ</span>'
        else:                pq_cell = '<span class="badge muted">—</span>'
        group_rows += (
            f"<tr><td>{_html_escape(g.protocol)}</td>"
            f"<td><code>{_html_escape(g.name)}</code></td>"
            f"<td>{g.bits}</td>"
            f"<td>{_badge_html(g.strength)}</td>"
            f"<td>{pq_cell}</td></tr>"
        )
    group_table = (
        "<table><thead><tr><th>Protocol</th><th>Group</th><th>Bits</th>"
        "<th>Strength</th><th>PQ</th></tr></thead>"
        f"<tbody>{group_rows}</tbody></table>"
        if group_rows else ""
    )

    # ----- Certificate -----
    c = pr.cert
    cert_table = ""
    if c.subject or c.issuer:
        rows = [
            ("Subject", f"<code>{_html_escape(c.subject)}</code>"),
            ("Subject Alt Names",
             f"<code>{_html_escape(c.altnames)}</code>" if c.altnames else "—"),
            ("Issuer", f"<code>{_html_escape(c.issuer)}</code>"),
            ("Signature algorithm", f"<code>{_html_escape(c.signature_algorithm)}</code>"
             + (' <span class="badge good">PQ</span>' if c.is_pq_signed() else '')),
            ("Public key", _html_escape(
                f"{c.pk_type} {c.pk_bits}-bit"
                + (f" ({c.pk_curve})" if c.pk_curve else "")
            )),
            ("Self-signed", _html_escape(c.self_signed)),
            ("Not before", _html_escape(c.not_before)),
            ("Not after",
             f"<span class=\"badge bad\">EXPIRED — {_html_escape(c.not_after)}</span>"
             if c.expired == "true" else _html_escape(c.not_after)),
        ]
        cert_table = "<table><tbody>" + "".join(
            f"<tr><th>{_html_escape(k)}</th><td>{v}</td></tr>"
            for k, v in rows
        ) + "</tbody></table>"

    return f"""
<details class="port collapsible" open>
  <summary>
    <strong>Port {pr.port}</strong>
    {_badge_html(pr.overall_strength())}
    {_pq_kind_badge(pr.pq_kex_kind())}
  </summary>
  <div class="body">
    <h4>Checks</h4>{checks_table}
    <h4>Protocols</h4>{proto_table}
    <h4>Cipher suites</h4>{cipher_table}
    {("<h4>Key-exchange groups</h4>" + group_table) if group_table else ""}
    {("<h4>Certificate</h4>" + cert_table) if cert_table else ""}
  </div>
</details>
"""


# ---------------------------------------------------------------------------
# Report dispatcher
# ---------------------------------------------------------------------------

def render_one(fmt, hosts, args, scan_date, domain_meta, domain_count,
               run_meta: "RunMetadata | None" = None) -> str:
    if fmt == "csv":
        return render_csv(hosts, run_meta=run_meta)
    if fmt == "json":
        return render_json(hosts, args, scan_date, domain_meta, run_meta=run_meta)
    if fmt == "html":
        return render_html(hosts, args, scan_date, domain_meta, domain_count,
                           run_meta=run_meta)
    return render_md(hosts, args, scan_date, domain_meta, domain_count,
                     run_meta=run_meta)


def main() -> int:
    args = parse_args()

    global STRICT_PQ, MIN_SCORE_RANK
    STRICT_PQ = bool(args.strict_pq)
    MIN_SCORE_RANK = _strength_rank(args.min_score) if args.min_score else None

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColorFormatter(use_colour=sys.stderr.isatty()))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.DEBUG if args.verbose else logging.INFO)

    started = datetime.now(timezone.utc)
    scan_date = started.strftime("%Y-%m-%d %H:%M UTC")
    sslscan = args.sslscan_path or _find_sslscan()
    log.debug("Using sslscan at: %s", sslscan)
    if STRICT_PQ:
        log.info("Strict PQ mode: endpoints without post-quantum KEX will be "
                 "treated as findings")
    if MIN_SCORE_RANK is not None:
        log.info("Min-score gate: endpoints scored below '%s' will be treated "
                 "as findings", args.min_score)

    # Provenance / reproducibility record — captured up-front, finalised
    # below after orchestration so duration_s is real.
    run_meta = collect_run_metadata(args, sslscan, started.isoformat())

    domains = load_domains(args.domains) if args.domains else []
    cidrs = args.cidr or []

    log.info("Resolving DNS for %d domain(s) …", len(domains))
    domain_meta = resolve_all_domains(domains)

    jobs = plan_jobs(
        sslscan, domains, cidrs, args.ports, domain_meta,
        args.connect_timeout, args.socket_timeout,
        args.iana_names, args.show_times,
    )
    results_map = run_all_jobs(jobs, args.workers, domain_meta)
    hosts = list(results_map.values())
    n_reachable = sum(1 for h in hosts if h.reachable_ports())
    n_flagged   = sum(1 for h in hosts if h.has_findings())
    finished = datetime.now(timezone.utc)
    run_meta.finished_utc = finished.isoformat()
    run_meta.duration_s = (finished - started).total_seconds()
    log.info("Scan complete in %.1fs. %d endpoint(s) scanned, %d reachable, %d with findings.",
             run_meta.duration_s, len(hosts), n_reachable, n_flagged)

    formats: list[str] = args.format
    kwargs = dict(hosts=hosts, args=args, scan_date=scan_date,
                  domain_meta=domain_meta, domain_count=len(domains),
                  run_meta=run_meta)

    if len(formats) == 1:
        report = render_one(formats[0], **kwargs)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            log.info("Report written to %s", args.output)
        else:
            sys.stdout.write(report)
    else:
        stem = args.output or f"sslscan_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not args.output:
            log.info("No --output given; using stem '%s'", stem)
        for fmt in formats:
            path = f"{stem}.{fmt}"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render_one(fmt, **kwargs))
            log.info("Wrote %s → %s", fmt.upper(), path)

    # Exit code: 0 clean, 1 findings present.  Execution errors raise and
    # produce 2 via the wrapper below.
    return 1 if n_flagged > 0 else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.error("Interrupted")
        sys.exit(130)
    except Exception as exc:
        log.error("Fatal: %s", exc)
        sys.exit(2)
