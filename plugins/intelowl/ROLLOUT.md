# IntelOwl Plugin Rollout and Monitoring Plan (staging-safe)

Scope
- External enrichment plugin that queries IntelOwl for IOC intelligence and publishes namespaced enrichment fields to Redis Streams.
- Default profile is staging-safe: query-only mode, conservative rate limits, two-layer cache, and dry-run support.

References
- Source: [plugins/intelowl](console-ir/plugins/intelowl)
- Entry point: [main.go](console-ir/plugins/intelowl/main.go)
- Client(s): [NewRealIntelOwlClient()](console-ir/plugins/intelowl/client.go:79), [NewMockIntelOwlClient()](console-ir/plugins/intelowl/client.go:197)
- Cache: [NewCacheManager()](console-ir/plugins/intelowl/cache.go:154)
- Enrichment mapping: [convertToEnrichmentFields()](console-ir/plugins/intelowl/enrichment.go:11)
- E2E test runner: [test-plugin.sh](console-ir/plugins/intelowl/test-plugin.sh:1)
- Config example: [config.yaml](console-ir/plugins/intelowl/config.yaml)

Environment variables
- INTEL_OWL_URL
- INTEL_OWL_TOKEN

Key flags (subset)
- --intelowl-url, --api-key, --verify-tls, --timeout
- --redis, --group, --consumer
- --mode query|submit (default query)
- --poll-interval 2s, --poll-timeout 60s, --max-concurrent 2
- --rate-limit-rps 5, --burst-limit 10
- --use-redis-cache true, --cache-ttl 4h, --cache-size 2000
- --analyzers-* per type, --exclude-analyzers
- --min-confidence low
- --dry-run

1) Build
Linux/macOS
- cd console-ir/plugins/intelowl
- go mod tidy
- go build -o ../../bin/intelowl-plugin .

Windows
- cd console-ir/plugins/intelowl
- go mod tidy
- go build -o ..\..\bin\intelowl-plugin.exe .

2) Staging rollout checklist
- Use staging-safe defaults (query-only, RPS 5, burst 10, max-concurrent 2, cache-ttl 4h).
- Provide IntelOwl URL/token via env or flags; if missing, the plugin falls back to mock client.
- Validate with E2E:
  - From repo root: ./console-ir/plugins/intelowl/test-plugin.sh
  - Confirms build, unit tests, dry-run execution, minimal Redis connectivity, and writes a test report (intelowl-test-report-YYYYmmdd-HHMMSS.txt).
- Start plugin in staging:
  - ./bin/intelowl-plugin --mode query --redis redis://localhost:6379
  - Optionally specify analyzers per type with --analyzers-ip/domain/url/hash/email; defaults are minimal (empty) to rely on server presets or conservative behavior.

3) Monitoring
- Process liveness (systemd or container health).
- Logs: API errors, cache hits/misses, events processed, enrichments published, average processing time.
- Redis Streams:
  - Group info: redis-cli XINFO GROUPS events
  - Consumers info: redis-cli XINFO CONSUMERS events console-ir-intelowl
  - Stream length: redis-cli XLEN events
- Alert suggestions:
  - API 401/403 (token issues)
  - API 429/5xx bursts (throttling or server-side errors)
  - Persistent high pending count or consumer idle time
  - Crash loops or frequent restarts

4) Performance tuning
- Rate limits: start with --rate-limit-rps 5 --burst-limit 10; increase cautiously.
- Cache: adjust --cache-ttl and --cache-size; keep use-redis-cache true for multi-instance sharing.
- Scope: constrain analyzers per type; add --exclude-analyzers as needed.
- Batch: XReadGroup Count is modest (4) by default in [processEvents()](console-ir/plugins/intelowl/main.go:272).

5) Security and privacy
- Use environment variables for secrets; avoid putting tokens on the command line.
- Keep --verify-tls true for production.
- Query-only mode by default to avoid submitting sensitive artifacts. Submission can be enabled explicitly after a risk review.

6) Systemd example (Linux)
File: /etc/systemd/system/console-ir-intelowl.service
[Unit]
Description=Console-IR IntelOwl Enrichment Plugin
After=network-online.target redis.service
Wants=network-online.target

[Service]
Type=simple
User=consoleir
Group=consoleir
Environment=INTEL_OWL_URL=https://intelowl.example.com
Environment=INTEL_OWL_TOKEN=REDACTED
ExecStart=/opt/console-ir/bin/intelowl-plugin --redis redis://localhost:6379 --mode query --verify-tls true --rate-limit-rps 5 --burst-limit 10 --cache-ttl 4h --use-redis-cache true
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target

Commands
- systemctl daemon-reload
- systemctl enable --now console-ir-intelowl
- journalctl -u console-ir-intelowl -f

7) Rollback
- Stop service: systemctl stop console-ir-intelowl
- Verify consumer stopped: redis-cli XINFO CONSUMERS events console-ir-intelowl
- Revert binary/config to last known good
- Start service and monitor logs and Redis lag

8) SLOs and KPIs (initial)
- Availability: > 99.5%
- Median enrichment latency: < 1s per event (staging)
- API error rate: < 1% over 30 minutes
- Redis pending: < 1000 sustained
- No unexpected 401/403 events

Notes
- Submit-and-wait against live IntelOwl is intentionally not enabled by default in this version to protect staging. Mock submission is covered in tests; live submission can be enabled in a follow-up increment with production guardrails.