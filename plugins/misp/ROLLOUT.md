# MISP Plugin Rollout and Monitoring Plan

This document provides a practical rollout, operations, and monitoring plan for the MISP enrichment plugin in Console‑IR.

References:
- Source: [plugins/misp](console-ir/plugins/misp)
- Main entry point: [console-ir/plugins/misp/main.go](console-ir/plugins/misp/main.go)
- Build target (Makefile): [console-ir/Makefile](console-ir/Makefile)
- PowerShell builder (Windows): [console-ir/scripts/build-plugins.ps1](console-ir/scripts/build-plugins.ps1)
- E2E test runner: [console-ir/plugins/misp/test-plugin.sh](console-ir/plugins/misp/test-plugin.sh:1)
- Example config: [console-ir/plugins/misp/config.yaml](console-ir/plugins/misp/config.yaml)

Key functions:
- Client: [NewMISPClient()](console-ir/plugins/misp/client.go:104)
- Cache: [NewCacheManager()](console-ir/plugins/misp/cache.go:272)
- Consumer loop: [processEvents()](console-ir/plugins/misp/main.go:304)
- Observable extraction: [extractObservables()](console-ir/plugins/misp/main.go:427)

---

## 1) Goals and Scope
- Enrich OCSF events with MISP threat intelligence via Redis streams.
- Respect TLP and org/tag filters; minimize API load using rate‑limiting and caching.
- Provide safe staged rollout, with measurable health, SLOs, and rollback steps.

---

## 2) Artifacts and Locations
- Linux/macOS (Makefile):
  - Output binary: bin/misp-plugin
  - Target to build only MISP: `make plugin-misp`
  - Target to build all plugins: `make build-plugins`
- Windows (PowerShell):
  - Output binary: bin/misp (plugin name is folder name)
  - Script: `.\console-ir\scripts\build-plugins.ps1 -Plugin misp`

Notes:
- The Makefile and PowerShell outputs differ (`misp-plugin` vs `misp`) by design; pick the one consistent with your platform/process.

---

## 3) Prerequisites
- Redis reachable (default redis://localhost:6379).
- Valid MISP base URL and API key with read access.
- Outbound egress from plugin host to MISP over HTTPS.
- Time sync on host (for TTLs, rate limiting, logs).

---

## 4) Configuration
Options can be passed as flags or environment variables (where applicable).

Environment variables:
- MISP_URL: base URL (e.g., https://misp.example.com)
- MISP_API_KEY: API key string

Common flags (subset):
- --redis redis://localhost:6379
- --misp-url https://misp.example.com
- --api-key $MISP_API_KEY
- --verify-tls true|false
- --timeout 30s
- --rate-limit-rps 10
- --burst-limit 20
- --cache-ttl 4h
- --cache-size 2000
- --use-redis-cache true
- --days-back 30
- --only-to-ids true
- --include-context true
- --max-results 100
- --correlate-events true
- --max-correlations 10
- --process-ips true --process-domains true --process-hashes true --process-urls true --process-emails false
- --min-threat-level 3
- --excluded-orgs "OrgA,OrgB"
- --required-tags "tlp:white,confidence:high"
- --consumer "misp-plugin"
- --group "console-ir-misp"
- --dry-run

See [console-ir/plugins/misp/config.yaml](console-ir/plugins/misp/config.yaml) for a configuration example.

---

## 5) Build and Package

Linux/macOS:
- Build just MISP plugin:
  - make plugin-misp
  - Output: bin/misp-plugin
- Build all plugins:
  - make build-plugins

Windows:
- PowerShell builder:
  - .\console-ir\scripts\build-plugins.ps1 -Plugin misp
  - Output: .\bin\misp

---

## 6) Staging Rollout Checklist

1. Build
   - Linux/macOS: `make plugin-misp`
   - Windows: `.\console-ir\scripts\build-plugins.ps1 -Plugin misp`

2. Sanity tests
   - Dry‑run help: `bin/misp-plugin --dry-run --help` (no network side effects)
   - End‑to‑end: run [test-plugin.sh](console-ir/plugins/misp/test-plugin.sh:1) from repo root:
     - `./console-ir/plugins/misp/test-plugin.sh`
     - Confirms build, unit tests, dry‑run, Redis connectivity, and generates a test report.

3. Redis/Streams smoke
   - Ensure Redis up (docker-compose up -d redis or managed).
   - Check consumer group creation on first run:
     - `redis-cli XINFO GROUPS events` (expect group console-ir-misp if started once)

4. Token & URL validation
   - In non-dry run, plugin validates key and MISP connectivity at startup:
     - see [initializeMISPClient()](console-ir/plugins/misp/main.go:215)

5. Limited exposure test
   - Configure minimal rate limits: `--rate-limit-rps 2 --burst-limit 4`
   - Narrow scopes: `--required-tags tlp:white --days-back 7`
   - Run for a short period; inspect logs and Redis enrichments.

6. Promotion gating
   - Promotion criteria:
     - API error rate < 1% over 30 mins
     - Redis consumer lag stable (see §8)
     - Avg process time steady (internal metrics updated via logs)

---

## 7) Production Deployment Options

Option A: Systemd service (recommended for host/bare‑metal)

Example unit (adjust binary path/name for your platform):

/etc/systemd/system/console-ir-misp.service
[Unit]
Description=Console-IR MISP Enrichment Plugin
After=network-online.target redis.service
Wants=network-online.target

[Service]
Type=simple
User=consoleir
Group=consoleir
Environment=MISP_URL=https://misp.example.com
Environment=MISP_API_KEY=REDACTED
ExecStart=/opt/console-ir/bin/misp-plugin --redis redis://localhost:6379 --verify-tls true --rate-limit-rps 10 --burst-limit 20 --cache-ttl 4h --use-redis-cache true
Restart=on-failure
RestartSec=5s
Nice=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target

Commands:
- systemctl daemon-reload
- systemctl enable --now console-ir-misp
- journalctl -u console-ir-misp -f

Option B: Docker/Compose (example pattern)
- Mount binary and run as a simple service sidecar to Redis/app.
- Ensure environment variables and flags are passed.
- Configure restart policy and resource limits.

---

## 8) Monitoring and Health

The plugin emits structured logs; it does not expose HTTP metrics. Monitor via:
- Process liveness (systemd or container health)
- Logs for error rate and timing
- Redis stream health and lag

Redis checks:
- Consumer groups:
  - `redis-cli XINFO GROUPS events`
  - Fields: consumers, pending, last-delivered-id
- Per-consumer lag (approx):
  - `redis-cli XINFO CONSUMERS events console-ir-misp`
  - Track `pending` and `idle` fields
- Stream cardinality trend:
  - `redis-cli XLEN events`
  - Sudden growth without ack suggests consumer issues

Alert suggestions:
- Process not running / restart loop
- Redis connectivity failures
- MISP API 401/403 (invalid/expired key)
- MISP API 429/5xx bursts (rate limiting or server-side)
- Rate limiter timeouts/log spam (“rate limit timeout”)
- Pending count > threshold for sustained period (e.g., >1000 for 10 min)

Dashboards:
- Logs: error rate, warnings, request timing (grep/select log patterns)
- Redis: stream len, pending, per-consumer idle, ack rates
- Host: CPU/mem for the plugin process

---

## 9) Performance and Tuning

- Rate limits:
  - Start conservative: `--rate-limit-rps 5 --burst-limit 10`
  - Increase gradually while observing 429/latency
- Cache:
  - Memory size via `--cache-size`
  - TTL via `--cache-ttl`
  - Redis cache toggle via `--use-redis-cache`
- Query scope:
  - Reduce `--days-back`
  - Use `--only-to-ids true`
  - Restrict `--required-tags` to trusted/tlp‑white tags
- Batch size:
  - XReadGroup Count is 8 in [processEvents()](console-ir/plugins/misp/main.go:327); adjust only if necessary.

---

## 10) Security and Compliance

- API key handling:
  - Prefer environment variables or systemd drop-in file with restricted perms.
  - Avoid CLI history exposure (don’t pass keys on the command line if possible).
- TLS:
  - Keep `--verify-tls true` in production.
  - `--verify-tls false` is only for non‑prod controlled contexts.
- TLP compliance:
  - Use `--required-tags` for tlp filtering (e.g., `tlp:white`).
- Org filtering:
  - `--excluded-orgs` to exclude untrusted intelligence sources.

---

## 11) Runbook (Day‑2 Ops)

Startup (systemd):
- `systemctl start console-ir-misp`
- `journalctl -u console-ir-misp -f`

Dry run (no external calls, safe on any host):
- `bin/misp-plugin --dry-run --redis redis://localhost:6379`

Functional E2E in repo:
- `./console-ir/plugins/misp/test-plugin.sh`

Redis quick checks:
- `redis-cli PING`
- `redis-cli XINFO GROUPS events`
- `redis-cli XINFO CONSUMERS events console-ir-misp`

Rate limit tune example:
- `--rate-limit-rps 8 --burst-limit 16`

Narrow scope example:
- `--required-tags tlp:white --days-back 7 --only-to-ids true`

---

## 12) Rollback

Immediate rollback procedure:
1) Stop the service
   - systemctl stop console-ir-misp
2) Verify consumer stopped
   - `redis-cli XINFO CONSUMERS events console-ir-misp`
3) Optional: Drain pending (advanced; only if needed and safe)
4) Revert to previous known-good binary/config
5) Start service and monitor

---

## 13) SLOs and KPIs (initial)

- Availability: plugin process up > 99.5%
- Mean Enrichment Latency: < 1s median per event (observed via logs/lag)
- API Error Rate: < 1% over 30 minutes
- Redis Pending: < 1000 sustained
- No 401/403 for MISP requests (key hygiene)

---

## 14) Future Enhancements

- Optional HTTP /metrics for Prometheus export (counters for API calls, latencies, cache hit ratio)
- Config file loader parity with flags
- Hot‑reload for configuration
- Circuit breaker for MISP API backoffs

---

Appendix:
- Core constructors and flow:
  - Client: [NewMISPClient()](console-ir/plugins/misp/client.go:104)
  - Cache: [NewCacheManager()](console-ir/plugins/misp/cache.go:272)
  - Event loop: [processEvents()](console-ir/plugins/misp/main.go:304)
  - Extraction: [extractObservables()](console-ir/plugins/misp/main.go:427)