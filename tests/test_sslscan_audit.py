"""
Tests for sslscan_audit.py.

Run:  pytest tests/
Deps: pip install pytest dnspython
"""
from __future__ import annotations

import ipaddress
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import sslscan_audit as sa
from sslscan_audit import (
    DEFAULT_PORTS,
    KNOWN_FINDING_TAGS,
    STARTTLS_PORTS,
    Certificate,
    Cipher,
    HostResult,
    KexGroup,
    PortResult,
    _worst_strength,
    _strength_rank,
    build_sslscan_cmd,
    diff_against_baseline,
    load_baseline,
    parse_sslscan_xml,
    plan_jobs,
    render_html,
    render_md,
    render_sarif,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# Minimal sslscan XML with a mix of strong/weak ciphers and a PQ group.
SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<document><ssltest host="example.com" ip="1.2.3.4" port="443">
  <protocol type="tls" version="1.3" enabled="1"/>
  <protocol type="tls" version="1.2" enabled="1"/>
  <protocol type="tls" version="1.1" enabled="0"/>
  <protocol type="tls" version="1.0" enabled="0"/>
  <protocol type="ssl" version="3"   enabled="0"/>
  <protocol type="ssl" version="2"   enabled="0"/>
  <heartbleed sslversion="TLSv1.3" vulnerable="0"/>
  <heartbleed sslversion="TLSv1.2" vulnerable="0"/>
  <renegotiation supported="1" secure="1"/>
  <compression supported="0"/>
  <fallback supported="1"/>
  <cipher status="preferred" sslversion="TLSv1.3" bits="256"
          cipher="TLS_AES_256_GCM_SHA384" id="0x1302" strength="strong"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="128"
          cipher="ECDHE-RSA-AES128-GCM-SHA256" id="0xC02F" strength="strong"
          curve="P-256" ecdhebits="256"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="128"
          cipher="RC4-SHA" id="0x0005" strength="weak"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="168"
          cipher="DES-CBC3-SHA" id="0x000A" strength="weak"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="128"
          cipher="ECDHE-RSA-AES128-SHA" id="0xC013" strength="acceptable"
          curve="P-256" ecdhebits="256"/>
  <group sslversion="TLSv1.3" bits="256" name="x25519"        strength="good"/>
  <group sslversion="TLSv1.3" bits="256" name="X25519MLKEM768" strength="good"/>
  <certificates>
    <certificate type="short">
      <subject>CN=example.com</subject>
      <altnames>DNS:example.com, DNS:www.example.com</altnames>
      <issuer>CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US</issuer>
      <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
      <pk bits="2048" type="RSA"/>
      <self-signed>false</self-signed>
      <not-valid-before>Jan  1 00:00:00 2025 GMT</not-valid-before>
      <not-valid-after>Jan  1 00:00:00 2026 GMT</not-valid-after>
      <expired>false</expired>
    </certificate>
  </certificates>
</ssltest></document>
"""

HEARTBLEED_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<document><ssltest host="vuln.example.com" ip="1.2.3.4" port="443">
  <protocol type="tls" version="1.2" enabled="1"/>
  <heartbleed sslversion="TLSv1.2" vulnerable="1"/>
  <renegotiation supported="1" secure="0"/>
  <compression supported="1"/>
  <fallback supported="0"/>
</ssltest></document>
"""

EXPIRED_CERT_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<document><ssltest host="old.example.com" ip="1.2.3.4" port="443">
  <protocol type="tls" version="1.2" enabled="1"/>
  <heartbleed sslversion="TLSv1.2" vulnerable="0"/>
  <renegotiation supported="0" secure="0"/>
  <cipher status="preferred" sslversion="TLSv1.2" bits="128"
          cipher="ECDHE-RSA-AES128-GCM-SHA256" id="0xC02F" strength="strong"
          curve="P-256" ecdhebits="256"/>
  <certificates>
    <certificate type="short">
      <subject>CN=old.example.com</subject>
      <altnames/>
      <issuer>CN=Old CA</issuer>
      <signature-algorithm>sha1WithRSAEncryption</signature-algorithm>
      <pk bits="1024" type="RSA"/>
      <self-signed>false</self-signed>
      <not-valid-before>Jan  1 00:00:00 2010 GMT</not-valid-before>
      <not-valid-after>Jan  1 00:00:00 2015 GMT</not-valid-after>
      <expired>true</expired>
    </certificate>
  </certificates>
</ssltest></document>
"""

PQ_CERT_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<document><ssltest host="pq.example.com" ip="1.2.3.4" port="443">
  <protocol type="tls" version="1.3" enabled="1"/>
  <heartbleed sslversion="TLSv1.3" vulnerable="0"/>
  <renegotiation supported="0" secure="0"/>
  <cipher status="preferred" sslversion="TLSv1.3" bits="256"
          cipher="TLS_AES_256_GCM_SHA384" id="0x1302" strength="strong"/>
  <group sslversion="TLSv1.3" bits="256" name="X25519MLKEM768" strength="good"/>
  <certificates>
    <certificate type="short">
      <subject>CN=pq.example.com</subject>
      <altnames/>
      <issuer>CN=PQ CA</issuer>
      <signature-algorithm>ML-DSA-65</signature-algorithm>
      <pk bits="2592" type="ML-DSA"/>
      <self-signed>false</self-signed>
      <not-valid-before>Jan  1 00:00:00 2025 GMT</not-valid-before>
      <not-valid-after>Jan  1 00:00:00 2026 GMT</not-valid-after>
      <expired>false</expired>
    </certificate>
  </certificates>
</ssltest></document>
"""


@pytest.fixture
def parsed():
    return parse_sslscan_xml(SAMPLE_XML, "example.com:443")


# ---------------------------------------------------------------------------
# 1. STARTTLS port mapping
# ---------------------------------------------------------------------------

class TestStarTTLSMapping:
    def test_expected_ports_present(self):
        expected = {21: "ftp", 25: "smtp", 110: "pop3", 143: "imap",
                    389: "ldap", 587: "smtp"}
        for port, proto in expected.items():
            assert STARTTLS_PORTS.get(port) == proto, \
                f"port {port} should map to '{proto}'"

    def test_implicit_tls_ports_absent(self):
        for port in (443, 465, 993, 995, 8443):
            assert port not in STARTTLS_PORTS, \
                f"port {port} should not be in STARTTLS_PORTS"

    def test_default_ports_include_starttls(self):
        for port in (25, 587, 110, 143):
            assert port in DEFAULT_PORTS, \
                f"port {port} missing from DEFAULT_PORTS"

    def test_default_ports_include_implicit_tls(self):
        for port in (443, 465, 993, 995):
            assert port in DEFAULT_PORTS


# ---------------------------------------------------------------------------
# 2. build_sslscan_cmd
# ---------------------------------------------------------------------------

class TestBuildSslscanCmd:
    def _cmd(self, port, sni=None, starttls=None):
        return build_sslscan_cmd(
            "sslscan",
            target_ip="1.2.3.4",
            port=port,
            sni=sni,
            connect_timeout=5,
            socket_timeout=5,
            iana_names=False,
            show_times=False,
            starttls=starttls,
        )

    def test_starttls_flag_added(self):
        cmd = self._cmd(25, sni="mail.example.com", starttls="smtp")
        assert "--starttls-smtp" in cmd

    def test_starttls_flag_absent_for_implicit_tls(self):
        cmd = self._cmd(443, sni="example.com", starttls=None)
        assert not any("starttls" in a for a in cmd)

    def test_all_starttls_ports_produce_correct_flag(self):
        for port, proto in STARTTLS_PORTS.items():
            cmd = self._cmd(port, starttls=proto)
            assert f"--starttls-{proto}" in cmd

    def test_sni_flag_present_when_given(self):
        cmd = self._cmd(443, sni="example.com")
        assert any(a.startswith("--sni-name=") for a in cmd)
        assert "--sni-name=example.com" in cmd

    def test_no_sni_flag_when_omitted(self):
        cmd = self._cmd(443, sni=None)
        assert not any("sni" in a for a in cmd)

    def test_target_is_last_argument(self):
        cmd = self._cmd(443, sni="example.com")
        assert cmd[-1] == "1.2.3.4:443"

    def test_starttls_appears_before_sni(self):
        cmd = self._cmd(25, sni="mail.example.com", starttls="smtp")
        assert cmd.index("--starttls-smtp") < cmd.index("--sni-name=mail.example.com")

    def test_xml_and_no_colour_always_present(self):
        cmd = self._cmd(443)
        assert "--xml=-" in cmd
        assert "--no-colour" in cmd

    def test_ipv6_target_bracketed(self):
        cmd = build_sslscan_cmd(
            "sslscan", target_ip="2001:db8::1", port=443, sni=None,
            connect_timeout=5, socket_timeout=5,
            iana_names=False, show_times=False,
        )
        assert cmd[-1] == "[2001:db8::1]:443"


# ---------------------------------------------------------------------------
# 3. --host classification (IP vs hostname)
# ---------------------------------------------------------------------------

class TestHostClassification:
    """The logic that splits --host values into domains / /32 CIDRs."""

    def _classify(self, hosts):
        domains, cidrs = [], []
        for h in hosts:
            try:
                ip = ipaddress.ip_address(h)
                cidrs.append(f"{h}/{ip.max_prefixlen}")
            except ValueError:
                domains.append(h)
        return domains, cidrs

    def test_hostname_goes_to_domains(self):
        domains, cidrs = self._classify(["mail.example.com"])
        assert domains == ["mail.example.com"]
        assert cidrs == []

    def test_ipv4_goes_to_cidr(self):
        domains, cidrs = self._classify(["10.0.0.5"])
        assert domains == []
        assert cidrs == ["10.0.0.5/32"]

    def test_ipv6_goes_to_cidr_as_single_address(self):
        # /128, not /32 — an IPv6 /32 would expand to 2^96 hosts.
        domains, cidrs = self._classify(["::1"])
        assert cidrs == ["::1/128"]

    def test_mixed_list_split_correctly(self):
        hosts = ["mail.example.com", "10.0.0.5", "smtp.example.com", "192.168.1.1"]
        domains, cidrs = self._classify(hosts)
        assert domains == ["mail.example.com", "smtp.example.com"]
        assert cidrs == ["10.0.0.5/32", "192.168.1.1/32"]

    def test_order_preserved(self):
        hosts = ["a.example.com", "1.1.1.1", "b.example.com"]
        domains, _ = self._classify(hosts)
        assert domains == ["a.example.com", "b.example.com"]


# ---------------------------------------------------------------------------
# 4. XML parsing
# ---------------------------------------------------------------------------

class TestParseSslscanXml:
    def test_returns_port_result(self, parsed):
        assert parsed is not None

    def test_reachable(self, parsed):
        assert parsed.reachable is True

    def test_protocols_parsed(self, parsed):
        assert parsed.protocols["TLSv1.3"] is True
        assert parsed.protocols["TLSv1.2"] is True
        assert parsed.protocols["TLSv1.1"] is False
        assert parsed.protocols["TLSv1.0"] is False
        assert parsed.protocols["SSLv3"]   is False
        assert parsed.protocols["SSLv2"]   is False

    def test_ciphers_parsed(self, parsed):
        names = [c.name for c in parsed.ciphers]
        assert "TLS_AES_256_GCM_SHA384" in names
        assert "ECDHE-RSA-AES128-GCM-SHA256" in names
        assert "RC4-SHA" in names

    def test_groups_parsed(self, parsed):
        names = [g.name for g in parsed.groups]
        assert "x25519" in names
        assert "X25519MLKEM768" in names

    def test_cert_parsed(self, parsed):
        assert "example.com" in parsed.cert.subject
        assert "sha256WithRSAEncryption" in parsed.cert.signature_algorithm
        assert parsed.cert.expired == "false"

    def test_renegotiation_parsed(self, parsed):
        assert parsed.renegotiation_supported == "1"
        assert parsed.renegotiation_secure == "1"

    def test_heartbleed_not_vulnerable(self, parsed):
        assert parsed.heartbleed_vulnerable == []

    def test_heartbleed_vulnerable(self):
        pr = parse_sslscan_xml(HEARTBLEED_XML, "vuln:443")
        assert "TLSv1.2" in pr.heartbleed_vulnerable

    def test_insecure_renegotiation_detected(self):
        pr = parse_sslscan_xml(HEARTBLEED_XML, "vuln:443")
        assert pr.renegotiation_supported == "1"
        assert pr.renegotiation_secure == "0"

    def test_compression_detected(self):
        pr = parse_sslscan_xml(HEARTBLEED_XML, "vuln:443")
        assert pr.compression_supported == "1"

    def test_fallback_not_supported(self):
        pr = parse_sslscan_xml(HEARTBLEED_XML, "vuln:443")
        assert pr.fallback_supported == "0"

    def test_expired_cert_parsed(self):
        pr = parse_sslscan_xml(EXPIRED_CERT_XML, "old:443")
        assert pr.cert.expired == "true"

    def test_invalid_xml_returns_none(self):
        assert parse_sslscan_xml("not xml at all", "x:443") is None

    def test_empty_xml_returns_none(self):
        assert parse_sslscan_xml("", "x:443") is None


# ---------------------------------------------------------------------------
# 5. Cipher weakness detection
# ---------------------------------------------------------------------------

class TestWeaknessDetection:
    def _cipher(self, name, protocol="TLSv1.2", bits=128):
        return Cipher(status="accepted", protocol=protocol, name=name,
                      bits=bits, cipher_id="0x0000", strength="weak")

    def test_rc4_flagged(self):
        assert "RC4" in self._cipher("RC4-SHA").weaknesses()

    def test_des_flagged(self):
        assert "DES/3DES" in self._cipher("DES-CBC3-SHA", bits=168).weaknesses()

    def test_sha1_mac_flagged(self):
        assert "SHA1-MAC" in self._cipher("ECDHE-RSA-AES128-SHA").weaknesses()

    def test_tls13_sha_not_flagged_as_sha1(self):
        c = Cipher(status="preferred", protocol="TLSv1.3",
                   name="TLS_AES_128_GCM_SHA256", bits=128,
                   cipher_id="0x1301", strength="strong")
        assert "SHA1-MAC" not in c.weaknesses()

    def test_no_pfs_flagged(self):
        assert "NO-PFS" in self._cipher("AES128-SHA").weaknesses()

    def test_ecdhe_not_flagged_no_pfs(self):
        assert "NO-PFS" not in self._cipher("ECDHE-RSA-AES128-GCM-SHA256").weaknesses()

    def test_null_cipher_flagged(self):
        assert "NULL" in self._cipher("NULL-SHA").weaknesses()

    def test_anon_cipher_flagged(self):
        assert "ANON" in self._cipher("ADH-AES128-SHA").weaknesses()

    def test_export_cipher_flagged(self):
        assert "EXPORT" in self._cipher("EXP-RC4-MD5").weaknesses()

    def test_cbc_on_old_tls_flagged(self):
        c = self._cipher("ECDHE-RSA-AES128-CBC-SHA", protocol="TLSv1.0")
        assert "CBC-OLD-TLS" in c.weaknesses()

    def test_cbc_on_tls12_not_flagged(self):
        c = self._cipher("ECDHE-RSA-AES128-CBC-SHA", protocol="TLSv1.2")
        assert "CBC-OLD-TLS" not in c.weaknesses()

    def test_clean_cipher_has_no_weaknesses(self):
        c = Cipher(status="preferred", protocol="TLSv1.3",
                   name="TLS_AES_256_GCM_SHA384", bits=256,
                   cipher_id="0x1302", strength="strong")
        assert c.weaknesses() == []

    # IANA (RFC) cipher names, as emitted under --iana-names, must be
    # classified identically to OpenSSL names.
    def test_iana_sha1_mac_flagged(self):
        c = self._cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
        assert "SHA1-MAC" in c.weaknesses()

    def test_iana_static_rsa_no_pfs_flagged(self):
        c = self._cipher("TLS_RSA_WITH_AES_128_GCM_SHA256")
        assert "NO-PFS" in c.weaknesses()

    def test_iana_tls13_suite_clean(self):
        c = Cipher(status="preferred", protocol="TLSv1.3",
                   name="TLS_AES_128_GCM_SHA256", bits=128,
                   cipher_id="0x1301", strength="strong")
        assert c.weaknesses() == []

    def test_weak_ciphers_detected_in_port_result(self, parsed):
        weak = parsed.weak_ciphers()
        names = [c.name for c, _ in weak]
        assert "RC4-SHA" in names
        assert "DES-CBC3-SHA" in names
        assert "TLS_AES_256_GCM_SHA384" not in names


# ---------------------------------------------------------------------------
# 5b. Certificate-level weakness detection
# ---------------------------------------------------------------------------

class TestCertificateWeaknesses:
    def test_expired_cert_flagged(self):
        assert "EXPIRED" in Certificate(expired="true").weaknesses()

    def test_sha1_signature_flagged(self):
        c = Certificate(signature_algorithm="sha1WithRSAEncryption")
        assert "SHA1-SIGNATURE" in c.weaknesses()

    def test_ecdsa_sha1_signature_flagged(self):
        c = Certificate(signature_algorithm="ecdsa-with-SHA1")
        assert "SHA1-SIGNATURE" in c.weaknesses()

    def test_md5_signature_flagged(self):
        c = Certificate(signature_algorithm="md5WithRSAEncryption")
        assert "MD5-SIGNATURE" in c.weaknesses()

    def test_sha256_signature_clean(self):
        c = Certificate(signature_algorithm="sha256WithRSAEncryption",
                        expired="false")
        assert c.weaknesses() == []

    def test_pq_signature_clean(self):
        c = Certificate(signature_algorithm="ML-DSA-65", expired="false")
        assert c.weaknesses() == []

    def test_expired_sha1_cert_is_a_finding(self):
        pr = parse_sslscan_xml(EXPIRED_CERT_XML, "old:443")
        assert set(pr.cert.weaknesses()) == {"EXPIRED", "SHA1-SIGNATURE"}
        assert pr.has_findings()

    def test_clean_pq_endpoint_has_no_findings(self):
        pr = parse_sslscan_xml(PQ_CERT_XML, "pq:443")
        assert not pr.has_findings()


# ---------------------------------------------------------------------------
# 5c. Finding tags & CI gates (--fail-on / --strict-pq-hybrid)
# ---------------------------------------------------------------------------

@pytest.fixture
def _restore_gates():
    """Snapshot and restore the module-level gate globals around a test."""
    saved = (sa.STRICT_PQ, sa.STRICT_PQ_HYBRID, sa.MIN_SCORE_RANK, sa.FAIL_ON)
    yield
    sa.STRICT_PQ, sa.STRICT_PQ_HYBRID, sa.MIN_SCORE_RANK, sa.FAIL_ON = saved


class TestFindingTags:
    def test_sample_xml_tags(self, parsed):
        tags = parsed.finding_tags()
        assert {"RC4", "DES/3DES", "SHA1-MAC", "NO-PFS"} <= tags
        # No gates active → no gate tags.
        assert not tags & {"NO-PQ", "NO-PQ-HYBRID", "BELOW-MIN-SCORE"}

    def test_vulnerable_host_tags(self):
        pr = parse_sslscan_xml(HEARTBLEED_XML, "vuln:443")
        assert {"HEARTBLEED", "TLS-COMPRESSION", "INSECURE-RENEG"} <= pr.finding_tags()

    def test_all_tags_are_known(self, parsed):
        pr = parse_sslscan_xml(HEARTBLEED_XML, "vuln:443")
        expired = parse_sslscan_xml(EXPIRED_CERT_XML, "old:443")
        for tags in (parsed.finding_tags(), pr.finding_tags(),
                     expired.finding_tags()):
            assert tags <= KNOWN_FINDING_TAGS

    def test_fail_on_restricts_exit_gate(self, parsed, _restore_gates):
        # SAMPLE_XML has RC4 etc. but no Heartbleed: with the gate narrowed
        # to HEARTBLEED the endpoint must not be flagged.
        sa.FAIL_ON = frozenset({"HEARTBLEED"})
        assert not parsed.has_findings()
        sa.FAIL_ON = frozenset({"RC4"})
        assert parsed.has_findings()

    def test_fail_on_no_pq_activates_gate(self, _restore_gates):
        pr = PortResult(port=443, reachable=True)
        assert not pr.has_findings()
        sa.FAIL_ON = frozenset({"NO-PQ"})
        assert "NO-PQ" in pr.finding_tags()
        assert pr.has_findings()

    def test_strict_pq_hybrid_flags_pure_pq(self, _restore_gates):
        pr = PortResult(port=443, reachable=True)
        pr.groups.append(KexGroup(protocol="TLSv1.3", name="MLKEM768",
                                  bits=256, strength="good"))
        assert not pr.has_findings()          # pure-PQ passes by default
        sa.STRICT_PQ_HYBRID = True
        assert "NO-PQ-HYBRID" in pr.finding_tags()
        assert pr.has_findings()
        # …and a hybrid group satisfies the gate.
        pr.groups.append(KexGroup(protocol="TLSv1.3", name="X25519MLKEM768",
                                  bits=256, strength="good"))
        assert not pr.has_findings()

    def test_strict_pq_satisfied_by_pure_pq(self, _restore_gates):
        pr = PortResult(port=443, reachable=True)
        pr.groups.append(KexGroup(protocol="TLSv1.3", name="MLKEM768",
                                  bits=256, strength="good"))
        sa.STRICT_PQ = True
        assert not pr.has_findings()


# ---------------------------------------------------------------------------
# 6. Post-quantum detection
# ---------------------------------------------------------------------------

class TestPQDetection:
    def _group(self, name, protocol="TLSv1.3", bits=256):
        return KexGroup(protocol=protocol, name=name, bits=bits, strength="good")

    def test_x25519mlkem768_is_pq(self):
        assert self._group("X25519MLKEM768").is_pq()

    def test_x25519mlkem768_is_hybrid(self):
        assert self._group("X25519MLKEM768").is_hybrid_pq()

    def test_secp256r1mlkem768_is_pq(self):
        assert self._group("SecP256r1MLKEM768").is_pq()

    def test_kyber_draft_is_pq(self):
        assert self._group("X25519Kyber768Draft00").is_pq()

    def test_kyber_draft_is_hybrid(self):
        assert self._group("X25519Kyber768Draft00").is_hybrid_pq()

    def test_mlkem768_pure_is_pq(self):
        assert self._group("MLKEM768").is_pq()

    def test_mlkem768_pure_not_hybrid(self):
        assert not self._group("MLKEM768").is_hybrid_pq()

    def test_x25519_classical_not_pq(self):
        assert not self._group("x25519").is_pq()

    def test_port_result_pq_kind_hybrid(self, parsed):
        assert parsed.pq_kex_kind() == "hybrid"

    def test_port_result_pq_kind_none_when_no_groups(self):
        pr = PortResult(port=443, reachable=True)
        assert pr.pq_kex_kind() == "none"

    def test_pq_cert_detection(self):
        pr = parse_sslscan_xml(PQ_CERT_XML, "pq:443")
        assert pr.cert.is_pq_signed()

    def test_classical_cert_not_pq_signed(self, parsed):
        assert not parsed.cert.is_pq_signed()


# ---------------------------------------------------------------------------
# 7. Strength ranking
# ---------------------------------------------------------------------------

class TestStrengthRanking:
    def test_known_order(self):
        ordered = ["null", "anonymous", "weak", "medium", "acceptable", "good", "strong"]
        ranks = [_strength_rank(l) for l in ordered]
        assert ranks == sorted(ranks)

    def test_unknown_label_is_worst(self):
        assert _strength_rank("bogus") < _strength_rank("null")

    def test_worst_strength_picks_lowest(self):
        assert _worst_strength(["strong", "weak", "good"]) == "weak"

    def test_worst_strength_empty_list(self):
        assert _worst_strength([]) == ""

    def test_port_result_overall_strength(self, parsed):
        # RC4-SHA is weak → overall should be weak
        assert parsed.overall_strength() == "weak"

    def test_port_result_worst_cipher(self, parsed):
        assert parsed.worst_cipher_strength() == "weak"


# ---------------------------------------------------------------------------
# 8. plan_jobs — STARTTLS wired through correctly
# ---------------------------------------------------------------------------

class TestPlanJobs:
    def test_starttls_port_gets_flag_in_job(self):
        jobs = plan_jobs(
            sslscan="sslscan",
            domains=["mail.example.com"],
            cidrs=[],
            ports=[25, 443],
            domain_meta={"mail.example.com": ([], ["1.2.3.4"])},
            connect_timeout=5, socket_timeout=5,
            iana_names=False, show_times=False,
        )
        job_25  = next(j for j in jobs if j.port == 25)
        job_443 = next(j for j in jobs if j.port == 443)
        assert job_25.starttls == "smtp"
        assert job_443.starttls is None
        assert "--starttls-smtp" in job_25.cmd
        assert not any("starttls" in a for a in job_443.cmd)

    def test_cidr_job_has_no_sni(self):
        jobs = plan_jobs(
            sslscan="sslscan",
            domains=[],
            cidrs=["10.0.0.1/32"],
            ports=[443],
            domain_meta={},
            connect_timeout=5, socket_timeout=5,
            iana_names=False, show_times=False,
        )
        assert jobs
        assert not any("sni" in a for a in jobs[0].cmd)

    def test_domain_job_has_sni(self):
        jobs = plan_jobs(
            sslscan="sslscan",
            domains=["example.com"],
            cidrs=[],
            ports=[443],
            domain_meta={"example.com": ([], ["1.2.3.4"])},
            connect_timeout=5, socket_timeout=5,
            iana_names=False, show_times=False,
        )
        assert any("--sni-name=example.com" in a for a in jobs[0].cmd)

    def test_domain_with_no_ips_produces_no_jobs(self):
        jobs = plan_jobs(
            sslscan="sslscan",
            domains=["unresolvable.example"],
            cidrs=[],
            ports=[443],
            domain_meta={"unresolvable.example": ([], [])},
            connect_timeout=5, socket_timeout=5,
            iana_names=False, show_times=False,
        )
        assert jobs == []


# ---------------------------------------------------------------------------
# 9. Markdown report — STARTTLS port heading
# ---------------------------------------------------------------------------

class TestMarkdownPortHeading:
    def _make_host(self, port):
        pr = parse_sslscan_xml(SAMPLE_XML.replace('port="443"', f'port="{port}"'), f"h:{port}")
        host = HostResult(target="example.com", ip="1.2.3.4", source="domain")
        host.ports[port] = pr
        return host

    def _render(self, port):
        args = SimpleNamespace(
            cidr=None, ports=[port], workers=1,
            strict_pq=False, min_score=None,
        )
        return render_md(
            hosts=[self._make_host(port)],
            args=args,
            scan_date="2026-01-01 00:00 UTC",
            domain_meta={"example.com": ([], ["1.2.3.4"])},
            domain_count=1,
        )

    def test_starttls_port_heading_annotated(self):
        md = self._render(25)
        assert "Port 25 (STARTTLS/SMTP)" in md

    def test_implicit_tls_port_heading_clean(self):
        md = self._render(443)
        assert "#### Port 443\n" in md
        assert "STARTTLS" not in md


# ---------------------------------------------------------------------------
# 9b. HTML report — at-a-glance charts
# ---------------------------------------------------------------------------

class TestHtmlCharts:
    def _render(self, hosts):
        args = SimpleNamespace(
            cidr=None, ports=[443], workers=1,
            strict_pq=False, min_score=None,
        )
        return render_html(
            hosts=hosts,
            args=args,
            scan_date="2026-01-01 00:00 UTC",
            domain_meta={h.target: ([], [h.ip]) for h in hosts},
            domain_count=len(hosts),
        )

    def _host(self, xml=SAMPLE_XML, target="example.com"):
        pr = parse_sslscan_xml(xml, f"{target}:443")
        host = HostResult(target=target, ip="1.2.3.4", source="domain")
        host.ports[443] = pr
        return host

    def test_chart_strip_present(self):
        html = self._render([self._host()])
        assert 'class="charts"' in html
        assert "Post-quantum key-exchange readiness" in html
        assert "sslscan strength" in html
        assert "Top finding tags" in html

    def test_pq_segments_reflect_data(self):
        # SAMPLE_XML offers X25519MLKEM768 → hybrid segment, no no-PQ segment.
        # (Match on segment titles — the cs-* class names always appear in
        # the embedded stylesheet regardless of data.)
        html = self._render([self._host()])
        assert 'title="hybrid PQ: 1"' in html
        assert 'title="no PQ' not in html

    def test_finding_tags_charted(self):
        html = self._render([self._host()])
        assert ">RC4</span>" in html       # hbar label for the RC4 tag

    def test_clean_host_shows_no_findings_message(self):
        html = self._render([self._host(xml=PQ_CERT_XML, target="pq.example.com")])
        assert "No findings across any port." in html

    def test_no_reachable_ports_no_chart_strip(self):
        host = HostResult(target="down.example.com", ip="1.2.3.4", source="domain")
        host.ports[443] = PortResult(port=443, reachable=False)
        html = self._render([host])
        assert 'class="charts"' not in html


# ---------------------------------------------------------------------------
# 10. SARIF output
# ---------------------------------------------------------------------------

class TestSarif:
    def _hosts(self):
        pr = parse_sslscan_xml(SAMPLE_XML, "example.com:443")
        host = HostResult(target="example.com", ip="1.2.3.4", source="domain")
        host.ports[443] = pr
        return [host]

    def test_valid_sarif_structure(self):
        import json
        doc = json.loads(render_sarif(self._hosts()))
        assert doc["version"] == "2.1.0"
        assert "sarif-schema-2.1.0" in doc["$schema"]
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "sslscan_audit"
        assert run["results"]

    def test_results_carry_rules_and_locations(self):
        import json
        doc = json.loads(render_sarif(self._hosts()))
        run = doc["runs"][0]
        rule_ids = {r["ruleId"] for r in run["results"]}
        assert {"RC4", "SHA1-MAC", "DES/3DES"} <= rule_ids
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert rule_ids <= declared
        loc = run["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == \
            "tls://example.com:443"

    def test_clean_host_produces_no_results(self):
        import json
        pr = parse_sslscan_xml(PQ_CERT_XML, "pq:443")
        host = HostResult(target="pq.example.com", ip="1.2.3.4", source="domain")
        host.ports[443] = pr
        doc = json.loads(render_sarif([host]))
        assert doc["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# 11. Baseline / regression diffing
# ---------------------------------------------------------------------------

class TestBaseline:
    def _host(self, xml=SAMPLE_XML, target="example.com", ip="1.2.3.4"):
        pr = parse_sslscan_xml(xml, f"{target}:443")
        host = HostResult(target=target, ip=ip, source="domain")
        host.ports[443] = pr
        return host

    def test_no_regressions_when_baseline_matches(self):
        host = self._host()
        baseline = {("example.com", "1.2.3.4", 443):
                    set(host.ports[443].finding_tags())}
        assert diff_against_baseline(baseline, [host]) == []

    def test_new_tag_is_a_regression(self):
        host = self._host()
        tags = set(host.ports[443].finding_tags())
        tags.discard("RC4")
        baseline = {("example.com", "1.2.3.4", 443): tags}
        regs = diff_against_baseline(baseline, [host])
        assert regs == [("example.com", "1.2.3.4", 443, ["RC4"])]

    def test_unknown_endpoint_counts_in_full(self):
        host = self._host(target="new.example.com")
        regs = diff_against_baseline({}, [host])
        assert len(regs) == 1
        assert "RC4" in regs[0][3]

    def test_fixed_finding_is_not_a_regression(self):
        # Baseline has MORE findings than current → clean diff.
        host = self._host(xml=PQ_CERT_XML, target="pq.example.com")
        baseline = {("pq.example.com", "1.2.3.4", 443): {"RC4", "SHA1-MAC"}}
        assert diff_against_baseline(baseline, [host]) == []

    def test_load_baseline_roundtrip(self, tmp_path):
        import json
        doc = {"endpoints": [{
            "target": "example.com", "ip": "1.2.3.4",
            "ports": [{"port": 443, "finding_tags": ["RC4", "SHA1-MAC"]}],
        }]}
        f = tmp_path / "base.json"
        f.write_text(json.dumps(doc))
        loaded = load_baseline(str(f))
        assert loaded == {("example.com", "1.2.3.4", 443): {"RC4", "SHA1-MAC"}}

    def test_load_baseline_rejects_old_schema(self, tmp_path):
        import json
        doc = {"endpoints": [{
            "target": "example.com", "ip": "1.2.3.4",
            "ports": [{"port": 443}],   # no finding_tags → pre-0.5.0
        }]}
        f = tmp_path / "old.json"
        f.write_text(json.dumps(doc))
        with pytest.raises(RuntimeError, match="finding_tags"):
            load_baseline(str(f))

    def test_load_baseline_rejects_non_report(self, tmp_path):
        f = tmp_path / "junk.json"
        f.write_text('{"foo": 1}')
        with pytest.raises(RuntimeError, match="endpoints"):
            load_baseline(str(f))


# ---------------------------------------------------------------------------
# 12. Integration tests (require sslscan + network; skipped by default)
# ---------------------------------------------------------------------------

integration = pytest.mark.skipif(
    shutil.which("sslscan") is None,
    reason="sslscan not on PATH",
)
network = pytest.mark.skipif(
    not shutil.which("sslscan"),
    reason="sslscan not on PATH",
)


@integration
class TestLiveScan:
    """Live scans against well-known public hosts. Skip with -m 'not integration'."""

    def _run(self, args_list):
        """Run the CLI via subprocess and return (returncode, stdout, stderr)."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent.parent / "sslscan_audit.py")]
            + args_list,
            capture_output=True, text=True, timeout=120,
        )
        return result

    def test_host_flag_hostname_scanned(self):
        r = self._run(["--host", "one.one.one.one", "--ports", "443", "--format", "md"])
        assert r.returncode in (0, 1)
        assert "one.one.one.one" in r.stdout
        assert "Port 443" in r.stdout

    def test_starttls_smtp_used_for_port_25(self):
        r = self._run([
            "--host", "smtp.gmail.com",
            "--ports", "25",
            "--format", "md",
            "--verbose",
        ])
        assert "--starttls-smtp" in r.stderr

    def test_port_443_no_starttls_flag(self):
        r = self._run([
            "--host", "one.one.one.one",
            "--ports", "443",
            "--format", "md",
            "--verbose",
        ])
        assert "starttls" not in r.stderr

    def test_starttls_heading_in_report(self):
        r = self._run([
            "--host", "smtp.gmail.com",
            "--ports", "25",
            "--format", "md",
        ])
        assert "Port 25 (STARTTLS/SMTP)" in r.stdout
