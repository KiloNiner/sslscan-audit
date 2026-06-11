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

**Dependencies:** Python ≥ 3.11, `dnspython`, and `sslscan` binary on PATH (for running the tool; not required for unit tests).

## Architecture

`sslscan_audit.py` is a single ~2500-line script with [PEP 723](https://peps.python.org/pep-0723/) inline dependency metadata (`pipx run` shebang). There are no packages, modules, or build steps.

### Data model

All data is held in dataclasses (no ORM, no database):

- `Cipher` — one accepted cipher suite; `weaknesses()` returns tags like `SHA1-MAC`, `NO-PFS`, `RC4`
- `KexGroup` — one offered TLS key-exchange group; `is_pq()` / `is_hybrid_pq()` detect post-quantum groups
- `Certificate` — parsed from sslscan's `<certificates>` XML element; `is_pq_signed()` detects ML-DSA/SLH-DSA/Falcon signatures; `weaknesses()` returns tags like `EXPIRED`, `SHA1-SIGNATURE`, `MD5-SIGNATURE`
- `PortResult` — aggregates ciphers, groups, cert, and vulnerability flags for one `(host, port)` scan; `has_findings()` is the single truth for whether this port counts as a finding
- `HostResult` — aggregates `PortResult`s for one `(target, ip)` pair; `has_findings()` delegates to its ports
- `Job` — holds the sslscan command list and metadata for one scan unit, created by `plan_jobs()`
- `RunMetadata` — provenance record (timing, CLI args, sslscan version) embedded in every output format

### Execution flow

```
parse_args()
  → load_domains() + split --host into domain/CIDR lists
  → resolve_all_domains()          # DNS CNAME chains + A records (thread pool)
  → plan_jobs()                    # build one Job per (ip, port) pair
  → run_all_jobs()                 # ThreadPoolExecutor, runs sslscan --xml=-
      → parse_sslscan_xml()        # ElementTree, returns PortResult
  → render_one() × N formats       # md / csv / json / html
  → exit 0 (clean) / 1 (findings) / 2 (error or zero scannable targets) / 130 (SIGINT)
```

### Key design decisions

**IP targeting with SNI:** Jobs always target the IP literal (`{ip}:{port}`) so round-robin DNS entries are each scanned individually. The original hostname is passed as `--sni-name=` so the server presents the correct certificate.

**STARTTLS auto-detection:** `STARTTLS_PORTS` maps port numbers to sslscan `--starttls-<proto>` flags. Ports absent from the map (443, 465, 993, …) are treated as implicit TLS.

**Global mutable CI gates:** `STRICT_PQ` and `MIN_SCORE_RANK` are module-level globals set once in `main()`. They are read by `PortResult.has_findings()` and the Markdown/HTML renderers. Changing their values in tests requires direct assignment.

**Subprocess timeout:** `proc_timeout = socket_timeout * SUBPROC_TIMEOUT_FACTOR + 30` — a hard wall-clock limit passed to `subprocess.run(timeout=…)`. This prevents stalled sslscan processes from blocking the thread pool indefinitely.

**Strength rollup:** `PortResult.overall_strength()` returns the *worst* sslscan strength label across all ciphers and groups for that port. Unknown labels rank below `null` (rank −1) so they never accidentally upgrade a suspicious result.

**CSV formula injection guard:** `_csv_safe()` prefixes values starting with `=`, `+`, `-`, `@`, tab, or CR with a single quote, protecting against spreadsheet formula injection.

**CSV reproducibility header:** The CSV preamble uses `#`-prefixed comment lines (pandas-compatible via `read_csv(comment="#")`) so run metadata is machine-readable even in flat-file consumers.

**HTML filter/expand:** The HTML report embeds inline CSS and a small JS snippet (`HTML_JS`) that wires up the filter input and expand/collapse buttons client-side. Run metadata is also embedded as an HTML comment (`<!-- … -->`) for grep-ability even with JS disabled.

### Output formats

All four formats (`md`, `csv`, `json`, `html`) are dispatched through `render_one()`. With a single `--format` the result goes to `--output` or stdout. With multiple formats, `--output` is used as a filename stem and the extension is appended (e.g. `report.md`, `report.json`).

### Tests

`tests/test_sslscan_audit.py` is a single file covering:

- STARTTLS port mapping
- `build_sslscan_cmd` flag construction
- `--host` IP vs hostname classification
- XML parsing (using embedded XML fixtures — no file I/O, no network)
- Cipher weakness detection
- Post-quantum group/cert detection
- Strength ranking and rollup
- `plan_jobs` STARTTLS/SNI wiring
- Markdown port heading format

Integration tests (`TestLiveScan`) are automatically skipped unless `sslscan` is on PATH. All other tests run without any external binary.
