# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Run the tool:**
```bash
pipx run ./sslscan_audit.py --host example.com --ports 443
# or, with dnspython already installed:
python sslscan_audit.py --domains targets.txt
```

**Run tests:**
```bash
pip install pytest dnspython
pytest tests/
# Skip live-network tests (requires sslscan on PATH):
pytest tests/ -m "not integration"
# Run a single test class:
pytest tests/test_sslscan_audit.py::TestWeaknessDetection
```

**Dependencies:** Python ≥ 3.11, `dnspython`, and `sslscan` binary on PATH (for running the tool; not required for unit tests). sslscan should be built from source with `make static` (see README): distro packages typically link an OpenSSL that is too old to negotiate ML-KEM hybrid groups and has legacy/weak ciphers compiled out, producing false negatives in both directions.

## Architecture

`sslscan_audit.py` is a single ~2500-line script with [PEP 723](https://peps.python.org/pep-0723/) inline dependency metadata (`pipx run` shebang). There are no packages, modules, or build steps.

### Data model

All data is held in dataclasses (no ORM, no database):

- `Cipher` — one accepted cipher suite; `weaknesses()` returns tags like `SHA1-MAC`, `NO-PFS`, `RC4`
- `KexGroup` — one offered TLS key-exchange group; `is_pq()` / `is_hybrid_pq()` detect post-quantum groups
- `Certificate` — parsed from sslscan's `<certificates>` XML element; `is_pq_signed()` detects ML-DSA/SLH-DSA/Falcon signatures; `weaknesses()` returns tags like `EXPIRED`, `SHA1-SIGNATURE`, `MD5-SIGNATURE`
- `PortResult` — aggregates ciphers, groups, cert, and vulnerability flags for one `(host, port)` scan; `finding_tags()` returns the canonical tag set (see `KNOWN_FINDING_TAGS`) and `has_findings()` (tags filtered by `FAIL_ON`) is the single truth for whether this port counts as a finding
- `HostResult` — aggregates `PortResult`s for one `(target, ip)` pair; `has_findings()` delegates to its ports
- `Job` — holds the sslscan command list and metadata for one scan unit, created by `plan_jobs()`
- `RunMetadata` — provenance record (timing, CLI args, sslscan version) embedded in every output format

### Execution flow

```
parse_args()
  → load_baseline()                # only with --baseline; fails fast on bad files
  → load_domains() + split --host into domain/CIDR lists
  → resolve_all_domains()          # DNS CNAME chains + A (and AAAA with --ipv6) records (thread pool)
  → plan_jobs()                    # build one Job per (ip, port) pair
  → run_all_jobs()                 # ThreadPoolExecutor, runs sslscan --xml=-
      → parse_sslscan_xml()        # ElementTree, returns PortResult
  → diff_against_baseline()        # only with --baseline; regressions drive exit code
  → render_one() × N formats       # md / csv / json / html / sarif
  → exit 0 (clean) / 1 (findings, or regressions with --baseline) / 2 (error or zero scannable targets) / 130 (SIGINT)
```

### Key design decisions

**IP targeting with SNI:** Jobs always target the IP literal (`{ip}:{port}`) so round-robin DNS entries are each scanned individually. The original hostname is passed as `--sni-name=` so the server presents the correct certificate.

**STARTTLS auto-detection:** `STARTTLS_PORTS` maps port numbers to sslscan `--starttls-<proto>` flags. Ports absent from the map (443, 465, 993, …) are treated as implicit TLS.

**Global mutable CI gates:** `STRICT_PQ`, `STRICT_PQ_HYBRID`, `MIN_SCORE_RANK`, and `FAIL_ON` are module-level globals set once in `main()`. They are read by `PortResult.finding_tags()` / `has_findings()` and the Markdown/HTML renderers. Changing their values in tests requires direct assignment (the `_restore_gates` fixture snapshots and restores them). Gate tags (`NO-PQ`, `NO-PQ-HYBRID`, `BELOW-MIN-SCORE`) are only emitted when the corresponding gate is active — either via its flag or by being named in `--fail-on`.

**Finding-tag taxonomy:** `KNOWN_FINDING_TAGS` is the canonical vocabulary shared by `--fail-on` validation, the JSON/CSV `finding_tags` fields, SARIF rule IDs (`SARIF_RULE_META`), and baseline diffing. Adding a new weakness check means adding its tag here and to `SARIF_RULE_META`.

**Baseline diffing:** `load_baseline()` only accepts JSON reports that carry per-port `finding_tags` (script ≥ 0.5.0) and fails loudly otherwise. `diff_against_baseline()` treats unknown endpoints as fully new, ignores disappeared endpoints, and respects `FAIL_ON`.

**Subprocess timeout:** `proc_timeout = socket_timeout * SUBPROC_TIMEOUT_FACTOR + 30` — a hard wall-clock limit passed to `subprocess.run(timeout=…)`. This prevents stalled sslscan processes from blocking the thread pool indefinitely.

**Strength rollup:** `PortResult.overall_strength()` returns the *worst* sslscan strength label across all ciphers and groups for that port. Unknown labels rank below `null` (rank −1) so they never accidentally upgrade a suspicious result.

**CSV formula injection guard:** `_csv_safe()` prefixes values starting with `=`, `+`, `-`, `@`, tab, or CR with a single quote, protecting against spreadsheet formula injection.

**CSV reproducibility header:** The CSV preamble uses `#`-prefixed comment lines (pandas-compatible via `read_csv(comment="#")`) so run metadata is machine-readable even in flat-file consumers.

**HTML filter/expand:** The HTML report embeds inline CSS and a small JS snippet (`HTML_JS`) that wires up the filter input and expand/collapse buttons client-side. Run metadata is also embedded as an HTML comment (`<!-- … -->`) for grep-ability even with JS disabled.

**HTML at-a-glance charts:** `_html_section_charts()` renders a chart strip at the top of the HTML report (PQ readiness stacked bar, strength-distribution stacked bar, top-finding-tags bar list) in pure HTML/CSS — no JS, no external chart library — so the report stays self-contained, printable, and renders with JS disabled. Series colours are `cs-*` classes shared between bar segments and legend dots.

### Output formats

All five formats (`md`, `csv`, `json`, `html`, `sarif`) are dispatched through `render_one()`. With a single `--format` the result goes to `--output` or stdout. With multiple formats, `--output` is used as a filename stem and the extension is appended (e.g. `report.md`, `report.json`). SARIF always reports every finding tag regardless of `--fail-on`.

### Tests

`tests/test_sslscan_audit.py` is a single file covering:

- STARTTLS port mapping
- `build_sslscan_cmd` flag construction
- `--host` IP vs hostname classification
- XML parsing (using embedded XML fixtures — no file I/O, no network)
- Cipher weakness detection (OpenSSL and IANA names)
- Certificate weakness detection (expiry, weak signature digests)
- Finding tags and CI gates (`--fail-on`, `--strict-pq-hybrid`)
- Post-quantum group/cert detection
- Strength ranking and rollup
- `plan_jobs` STARTTLS/SNI wiring
- Markdown port heading format
- SARIF structure and rule/result consistency
- Baseline loading and regression diffing

Integration tests (`TestLiveScan`) are automatically skipped unless `sslscan` is on PATH. All other tests run without any external binary.
