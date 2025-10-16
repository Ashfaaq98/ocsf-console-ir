# IntelOwl Enrichment Plugin (staging-safe profile)

IntelOwl-based external enrichment plugin for Console‑IR. It extracts observables from OCSF events, queries IntelOwl for intelligence, and publishes namespaced enrichment fields to the `enrichments` Redis stream.

This initial implementation favors safety for staging:
- Default mode is query-only
- Conservative rate limits and small batch sizes
- Two-layer caching (memory + optional Redis)
- Mock IntelOwl client used when URL/token are absent or when `--dry-run` is enabled

Links
- Source directory: [plugins/intelowl](console-ir/plugins/intelowl)
- Example config: [config.yaml](console-ir/plugins/intelowl/config.yaml)
- E2E test script: [test-plugin.sh](console-ir/plugins/intelowl/test-plugin.sh:1)
- Rollout plan: [ROLLOUT.md](console-ir/plugins/intelowl/ROLLOUT.md)

Key functions
- Client factory: [NewRealIntelOwlClient()](console-ir/plugins/intelowl/client.go:79), [NewMockIntelOwlClient()](console-ir/plugins/intelowl/client.go:197)
- Cache: [NewCacheManager()](console-ir/plugins/intelowl/cache.go:154)
- Event processing: [processEvents()](console-ir/plugins/intelowl/main.go:233)
- Observable extraction: [extractObservables()](console-ir/plugins/intelowl/main.go:310)
- Enrichment mapping: [convertToEnrichmentFields()](console-ir/plugins/intelowl/enrichment.go:11)

## 1) Build

Linux/macOS:
```bash
cd console-ir/plugins/intelowl
go mod tidy
go build -o ../../bin/intelowl-plugin .
```

Windows PowerShell (from repository root):
```pwsh
cd console-ir/plugins/intelowl
go mod tidy
go build -o ..\..\bin\intelowl-plugin.exe .
```

## 2) Configuration

Environment variables:
- INTEL_OWL_URL
- INTEL_OWL_TOKEN

Flags (subset):
- --intelowl-url, --api-key, --verify-tls, --timeout
- --redis, --group, --consumer
- --mode query|submit (default query)
- --poll-interval 2s, --poll-timeout 60s, --max-concurrent 2
- --rate-limit-rps 5, --burst-limit 10
- --use-redis-cache true, --cache-ttl 4h, --cache-size 2000
- --analyzers-ip, --analyzers-domain, --analyzers-url, --analyzers-hash, --analyzers-email
- --exclude-analyzers
- --min-confidence low
- --dry-run

Reference: [config.yaml](console-ir/plugins/intelowl/config.yaml)

Staging-safe defaults:
- mode=query
- rate-limit-rps=5, burst=10
- poll-interval=2s, poll-timeout=60s
- max-concurrent=2
- use-redis-cache=true, cache-ttl=4h
- minimal analyzer sets (empty by default; configurable)

## 3) Usage

Dry-run (mock IntelOwl):
```bash
./bin/intelowl-plugin --dry-run --redis redis://localhost:6379
```

Query-only with real IntelOwl (falls back to mock if URL/token missing):
```bash
export INTEL_OWL_URL=https://intelowl.example.com
export INTEL_OWL_TOKEN=YOUR_TOKEN
./bin/intelowl-plugin --mode query --redis redis://localhost:6379
```

Note: Live submit-and-wait path is intentionally not enabled against real IntelOwl in this version. Use `--dry-run` or query-only for staging; submission is available via mock for tests.

## 4) Enrichment fields

Per observable, fields are prefixed:
```
intelowl_{type}_{sanitized_value}_*
```

Examples:
- intelowl_ip_1_2_3_4_artifact
- intelowl_ip_1_2_3_4_verdict
- intelowl_ip_1_2_3_4_confidence
- intelowl_ip_1_2_3_4_tags
- intelowl_ip_1_2_3_4_analyzers
- intelowl_ip_1_2_3_4_jobs
- intelowl_ip_1_2_3_4_evidence_count
- intelowl_ip_1_2_3_4_summary
- intelowl_ip_1_2_3_4_per_analyzer_json (size-capped)

## 5) Testing

Unit/integration:
```bash
cd console-ir/plugins/intelowl
go test -v ./...
```

End-to-end script (from repo root):
```bash
./console-ir/plugins/intelowl/test-plugin.sh
```

This script builds the plugin, runs tests, exercises dry-run/Redis connectivity and generates a test report file in the plugin directory.

## 6) Rollout

See [ROLLOUT.md](console-ir/plugins/intelowl/ROLLOUT.md) for staging steps, monitoring, and rollback.