# sslscan-audit

`sslscan_audit.py` is a Python wrapper that drives [`sslscan`](https://github.com/rbsec/sslscan)
across large lists of hosts so you can audit TLS configuration in bulk — across
whole subnets, domain lists, or both at once — and get a single consolidated
report.

It runs `sslscan --xml=-` per `(host, port)` pair, parses the XML directly (no
scraping of human-readable output), and produces a posture report covering:

* Enabled / disabled protocol versions (SSLv2/v3, TLS 1.0–1.3)
* Every accepted cipher suite with key size, ECDHE curve, bit strength and
  per-cipher weakness tags (NULL, anon, EXPORT, RC4, DES/3DES, SHA1-MAC,
  CBC on legacy TLS, no-PFS)
* TLS 1.3 / 1.2 supported key-exchange groups, including post-quantum hybrids
  (`X25519MLKEM768`, `SecP256r1MLKEM768`, `X25519Kyber768Draft00`, …)
* Certificate details (subject, SANs, issuer, signature algorithm, validity,
  PQ signature detection) with certificate-level findings (expired,
  SHA-1/MD5 signature)
* Vulnerability flags: Heartbleed, insecure renegotiation, CRIME (TLS
  compression), `TLS_FALLBACK_SCSV`
* Per-endpoint sslscan strength score and post-quantum handshake readiness
* A canonical per-port finding-tag taxonomy driving granular CI gates
  (`--fail-on`, `--strict-pq`, `--strict-pq-hybrid`, `--min-score`),
  SARIF 2.1.0 output, and baseline/regression diffing (`--baseline`)

## Requirements

* Python 3.11 or newer
* [`sslscan`](https://github.com/rbsec/sslscan) on `PATH`
  (or pass `--sslscan-path`) — **build it from source**, see below
* [`dnspython`](https://pypi.org/project/dnspython/) (used to resolve domains
  and follow CNAME chains)

### Building sslscan from source (strongly recommended)

Distribution packages of [`sslscan`](https://github.com/rbsec/sslscan) are
typically too old for this tool's purposes, in both directions:

* **Post-quantum false negatives** — distro builds link the system OpenSSL,
  which usually predates OpenSSL 3.5 (the first release with built-in
  ML-KEM). Such a build can never negotiate `X25519MLKEM768` or the other
  hybrid groups, so every endpoint reads as *no PQ support* regardless of
  what the server actually offers.
* **Legacy false negatives** — system OpenSSL is compiled with SSLv2/SSLv3,
  EXPORT, and other weak ciphers removed. A scanner can only detect what its
  own library can still speak, so servers that *do* accept those
  "non-production" ciphers go unnoticed — exactly the findings an audit
  exists to catch.

Build the statically-linked variant instead, which compiles its own pinned
OpenSSL with legacy protocols and weak/insecure ciphers *enabled for test
purposes* (this is also the build the sslscan project itself recommends):

```bash
git clone https://github.com/rbsec/sslscan
cd sslscan
make static
sudo install -m 0755 sslscan /usr/local/bin/sslscan
# …or skip the install and point the audit at it directly:
#   sslscan_audit.py --sslscan-path /path/to/sslscan/sslscan …
```

Version guidance:

* sslscan ≥ 2.1 is required for key-exchange-group reporting (the `<group>`
  XML elements this tool parses).
* For ML-KEM hybrid detection, use a current release (≥ 2.2) so the bundled
  OpenSSL is ≥ 3.5.

To verify your build: `sslscan --version` should report a `-static` build
and the bundled OpenSSL version (the audit records this banner in every
report's run-metadata block, so reports are self-documenting). As a
functional check, scan a known PQ-enabled endpoint and confirm the hybrid
group shows up:

```bash
sslscan_audit.py --host cloudflare.com --ports 443 | grep -i mlkem
```


The script ships with [PEP 723](https://peps.python.org/pep-0723/) inline
metadata and a `pipx run` shebang, so the simplest way to run it is:

```bash
pipx run ./sslscan_audit.py --domains targets.txt
```

`pipx` will create an isolated venv with the right Python and `dnspython`
version. Alternatively, install `dnspython` yourself and invoke it as a
regular script:

```bash
pip install dnspython
python sslscan_audit.py --domains targets.txt
```

## Arguments

### Targets

At least one of `--host`, `--cidr`, or `--domains` is required; they may be combined freely.

| Flag | Description |
| --- | --- |
| `--host HOST [HOST ...]` | One or more hostnames or IP addresses to scan directly. Hostnames are resolved via DNS (CNAME chains followed, SNI set); bare IP addresses are scanned without SNI, equivalent to a single-address CIDR entry (`/32` for IPv4, `/128` for IPv6). |
| `--cidr CIDR [CIDR ...]` | One or more subnets in CIDR notation (e.g. `10.0.0.0/24 192.168.1.0/28`). Every host in each subnet is scanned without SNI. |
| `--domains FILE` | Path to a file with one domain per line. Blank lines and lines starting with `#` are ignored. Each domain is resolved via DNS (CNAME chains are followed). |
| `--ports PORT [PORT ...]` | Ports to probe. Default: `21 25 110 143 389 443 465 587 993 995 8443`. Ports with a well-known STARTTLS mapping (see below) automatically receive `--starttls-<proto>`; all others are treated as implicit TLS. |
| `--ipv6` | Also resolve AAAA records and scan the resulting IPv6 addresses (requires IPv6 connectivity from the scanning host). Bare IPv6 literals given via `--host`/`--cidr` are always scanned regardless of this flag. |

### STARTTLS port mapping

The following ports automatically trigger the corresponding `--starttls-<proto>` sslscan flag.
Any other port (443, 465, 993, …) is treated as direct / implicit TLS.

| Port | Protocol | sslscan flag |
| --- | --- | --- |
| 21 | FTP | `--starttls-ftp` |
| 25 | SMTP | `--starttls-smtp` |
| 110 | POP3 | `--starttls-pop3` |
| 143 | IMAP | `--starttls-imap` |
| 389 | LDAP | `--starttls-ldap` |
| 587 | SMTP submission | `--starttls-smtp` |
| 3306 | MySQL | `--starttls-mysql` |
| 5222 | XMPP client | `--starttls-xmpp` |
| 5432 | PostgreSQL | `--starttls-psql` |

### sslscan tuning

| Flag | Default | Description |
| --- | --- | --- |
| `--workers N` | `20` | Maximum parallel sslscan processes. |
| `--connect-timeout N` | `5` | Seconds passed to `sslscan --connect-timeout` (TCP connect). |
| `--socket-timeout N` | `5` | Seconds passed to `sslscan --timeout` (per-socket I/O). |
| `--sslscan-path PATH` | auto | Explicit path to the `sslscan` binary. Auto-detected from `PATH`, `/usr/local/bin`, `/usr/bin`, and (on Windows) `Program Files`. |
| `--iana-names` | off | Pass `--iana-names` to sslscan so cipher suites are reported using RFC names (`TLS_AES_128_GCM_SHA256`) instead of OpenSSL names (`AES128-GCM-SHA256`). |
| `--show-times` | off | Include per-handshake timing data (`sslscan --show-times`). |

### CI gates

These promote benign-looking configurations into findings so a CI run will
fail (exit code `1`) until they are fixed:

| Flag | Description |
| --- | --- |
| `--strict-pq` | Treat any endpoint that doesn't negotiate a post-quantum key-exchange group as a finding. Useful for enforcing PQ readiness across a fleet. |
| `--strict-pq-hybrid` | Like `--strict-pq`, but require a *hybrid* (PQ + classical) group specifically — endpoints offering only pure-PQ groups are also flagged. |
| `--min-score LABEL` | Treat any endpoint scored below `LABEL` as a finding. Choices, worst → best: `null`, `anonymous`, `weak`, `medium`, `acceptable`, `good`, `strong`. |
| `--fail-on TAG [TAG ...]` | Restrict the exit-code gate to specific finding tags (comma- or space-separated, case-insensitive). Reports still show every finding; only the named tags flag endpoints and drive exit code `1`. Naming `NO-PQ` or `NO-PQ-HYBRID` activates that PQ gate implicitly, so `--fail-on NO-PQ-HYBRID` alone gives you a CI run that fails *only* on missing hybrid PQ support. |
| `--baseline FILE` | Diff against a previous JSON report (`--format json`, script ≥ 0.5.0): exit `1` only if an endpoint:port shows a finding tag that wasn't in the baseline (a regression). Pre-existing findings are still reported but don't fail the run — ideal for ratcheting a fleet toward a target posture without a big-bang cleanup. |

### Finding tags

These are the values accepted by `--fail-on`, recorded per port in the JSON
(`finding_tags`) and CSV (`finding_tags` column) outputs, and used as SARIF
rule IDs:

| Tag | Source | Meaning |
| --- | --- | --- |
| `WEAK-PROTOCOL` | protocols | SSLv2/SSLv3/TLS 1.0/TLS 1.1 enabled |
| `NULL`, `ANON`, `EXPORT`, `DES/3DES`, `RC4`, `SHA1-MAC`, `CBC-OLD-TLS`, `NO-PFS` | cipher suites | Per-cipher weaknesses |
| `EXPIRED`, `SHA1-SIGNATURE`, `MD5-SIGNATURE` | certificate | Certificate expired / weak signature digest |
| `HEARTBLEED`, `TLS-COMPRESSION`, `INSECURE-RENEG` | handshake checks | Protocol-level vulnerabilities |
| `NO-PQ`, `NO-PQ-HYBRID`, `BELOW-MIN-SCORE` | CI gates | Only produced when the corresponding gate is active (via its flag or by being named in `--fail-on`) |

### Output

| Flag | Default | Description |
| --- | --- | --- |
| `--format FMT [FMT ...]` | `md` | One or more output formats. Choices: `md`, `csv`, `json`, `html`, `sarif`. The `sarif` format emits SARIF 2.1.0 with one rule per finding tag, suitable for GitHub code scanning and similar dashboards (SARIF always reports every finding, regardless of `--fail-on`). |
| `--output STEM` | stdout | Destination. With a single `--format` it's the filename; with multiple, it's a stem and the format extension is appended (e.g. `--output report --format md json` → `report.md`, `report.json`). |
| `--verbose`, `-v` | off | Enable DEBUG-level logging on stderr. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, no findings (with `--baseline`: no regressions). |
| `1` | Scan completed, one or more endpoints were flagged (weak ciphers/protocols, expired or weakly-signed certificates, vulnerabilities, or any CI gate hit). With `--fail-on`, only the named tags flag endpoints; with `--baseline`, only regressions versus the baseline. |
| `2` | Execution error (sslscan missing, no scannable targets after DNS resolution, fatal exception, etc.). `130` if interrupted with Ctrl-C. |

## Examples

Scan a single host directly:

```bash
sslscan_audit.py --host mail.example.com
```

Scan a mix of hostnames and IPs on the command line:

```bash
sslscan_audit.py --host mail.example.com smtp.example.com 10.0.0.5
```

Scan a single domain list, write a Markdown report to stdout:

```bash
sslscan_audit.py --domains targets.txt
```

Scan two subnets on the default ports and save Markdown to a file:

```bash
sslscan_audit.py --cidr 10.0.0.0/24 192.168.1.0/28 --output internal-tls.md
```

Combine domains and a subnet, probe non-default ports, and crank parallelism
up:

```bash
sslscan_audit.py \
  --domains prod-domains.txt \
  --cidr 10.20.0.0/22 \
  --ports 443 8443 9443 \
  --workers 40 \
  --output prod-tls.md
```

Emit Markdown, JSON, and HTML in one run (sharing a stem):

```bash
sslscan_audit.py --domains targets.txt --format md json html --output audit-2025
# → audit-2025.md, audit-2025.json, audit-2025.html
```

Use IANA cipher names and capture handshake timings:

```bash
sslscan_audit.py --domains targets.txt --iana-names --show-times --output report.md
```

CI gate — fail the build unless every reachable endpoint scores at least
`good` and negotiates a post-quantum key-exchange group:

```bash
sslscan_audit.py \
  --cidr 10.0.0.0/16 \
  --min-score good \
  --strict-pq \
  --format json --output ci-report.json
```

CI gate for a post-quantum rollout — fail *only* when an endpoint lacks a
hybrid PQ key exchange, while still reporting everything else:

```bash
sslscan_audit.py \
  --domains prod-domains.txt \
  --fail-on NO-PQ-HYBRID \
  --format json sarif --output pq-rollout
```

Ratchet mode — fail the build only on *regressions* against last week's
report (pre-existing findings are reported but tolerated):

```bash
sslscan_audit.py --domains targets.txt --format json --output this-week.json \
  --baseline last-week.json
```

Dual-stack scan including IPv6 endpoints, with SARIF for GitHub code
scanning:

```bash
sslscan_audit.py --domains targets.txt --ipv6 \
  --format sarif --output tls-audit.sarif
```

Point at a non-default `sslscan` binary (e.g. one you built from source with
PQ support):

```bash
sslscan_audit.py \
  --sslscan-path /opt/sslscan-pq/bin/sslscan \
  --domains targets.txt
```

Domain-list file format:

```text
# one host per line; comments and blank lines are ignored
example.com
api.example.com
mail.example.com
```
