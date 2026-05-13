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
  PQ signature detection)
* Vulnerability flags: Heartbleed, insecure renegotiation, CRIME (TLS
  compression), `TLS_FALLBACK_SCSV`
* Per-endpoint sslscan strength score and post-quantum handshake readiness

## Requirements

* Python 3.11 or newer
* [`sslscan`](https://github.com/rbsec/sslscan) on `PATH`
  (or pass `--sslscan-path`)
* [`dnspython`](https://pypi.org/project/dnspython/) (used to resolve domains
  and follow CNAME chains)

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

At least one of `--cidr` or `--domains` is required.

### Targets

| Flag | Description |
| --- | --- |
| `--cidr CIDR [CIDR ...]` | One or more subnets in CIDR notation (e.g. `10.0.0.0/24 192.168.1.0/28`). Every host in each subnet is scanned. |
| `--domains FILE` | Path to a file with one domain per line. Blank lines and lines starting with `#` are ignored. Each domain is resolved via DNS (CNAME chains are followed). |
| `--ports PORT [PORT ...]` | TLS ports to probe. Default: `443 8443 465 993 995`. |

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
| `--min-score LABEL` | Treat any endpoint scored below `LABEL` as a finding. Choices, worst → best: `null`, `anonymous`, `weak`, `medium`, `acceptable`, `good`, `strong`. |

### Output

| Flag | Default | Description |
| --- | --- | --- |
| `--format FMT [FMT ...]` | `md` | One or more output formats. Choices: `md`, `csv`, `json`, `html`. |
| `--output STEM` | stdout | Destination. With a single `--format` it's the filename; with multiple, it's a stem and the format extension is appended (e.g. `--output report --format md json` → `report.md`, `report.json`). |
| `--verbose`, `-v` | off | Enable DEBUG-level logging on stderr. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, no findings. |
| `1` | Scan completed, one or more endpoints were flagged (weak ciphers/protocols, vulnerabilities, or any CI gate hit). |
| `2` | Execution error (sslscan missing, fatal exception, etc.). `130` if interrupted with Ctrl-C. |

## Examples

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
