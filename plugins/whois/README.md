# WHOIS Plugin (External, Redis Streams)

The WHOIS plugin is an external executable that listens on the `events` Redis stream and publishes normalized WHOIS enrichments to the `enrichments` stream. It follows the external plugin contract described in [`docs/plugins.md`](../../docs/plugins.md) and is managed out-of-process by the Console-IR application.

Key implementation file:
- [`console-ir/plugins/whois/main.go`](./main.go)

Related references:
- Example external plugin design: [`console-ir/plugins/geoip/main.go`](../geoip/main.go:1)
- Plugin contract and configuration: [`console-ir/docs/plugins.md`](../../docs/plugins.md:1)

## Features

- Consumes events from Redis Streams (consumer group: `console-ir`)
- Extracts domains from event `raw_json` via simple JSON-key probes and regex fallback
- Performs WHOIS lookups with rate limiting and TTL caching
- Normalizes select WHOIS fields to flat key/value pairs:
  - registrar
  - created_date
  - expiration_date
  - nameservers
  - emails (deduplicated)
  - raw_snippet (truncated for safety)
- Publishes enrichments to the `enrichments` stream with `source=whois` and `type=whois`

Domain parsing and normalization anchors (for maintainers):
- Domain extraction entry: [extractDomains()](./main.go:146)
- WHOIS normalization: [normalizeWhois()](./main.go:237)

## Build

Build from the WHOIS module directory so the nested go.mod is used:

- Using local Go toolchain:
  - `cd console-ir/plugins/whois && go build -o ../../bin/whois .`

- Using Docker (golang image) to avoid local toolchain setup:
  - `docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/../..":/workspace -w /workspace/console-ir golang:1.25 sh -c 'cd /workspace/console-ir && go build -o bin/whois plugins/whois'`

The executable will be placed at `console-ir/bin/whois`.

## Run

You can run the plugin by pointing it to a reachable Redis server. Flags are defined at [`console-ir/plugins/whois/main.go`](./main.go:351).

Example (local Redis on default port):
- `./console-ir/bin/whois --redis "redis://localhost:6379" --consumer "whois-plugin"`

Flags:
- `--redis` (string): Redis connection URL. Default: `redis://localhost:6379`
- `--consumer` (string): Consumer name for Redis Streams. Default: `whois-plugin`
- `--timeout` (duration): WHOIS client timeout. Default: `5s`
- `--rate-limit-rps` (int): WHOIS requests per second. Default: `1`
- `--cache-ttl` (duration): TTL for WHOIS in-memory cache. Default: `24h`

Example with custom options:
- `./console-ir/bin/whois --redis "redis://localhost:6379" --consumer "whois-prod" --rate-limit-rps 2 --cache-ttl 12h`

## Streams Contract

The plugin consumes from the `events` stream in Redis and publishes to `enrichments`.

- Input (events stream) message shape (see [`console-ir/docs/plugins.md`](../../docs/plugins.md:7)):
  ```
  event_id: "evt_1234567890"
  event_type: "network"
  raw_json: "{...}"
  timestamp: 1642234567
  ```

- Output (enrichments stream) message shape:
  ```
  event_id: "evt_1234567890"
  source: "whois"
  type: "whois"
  data: "{\"whois_example_com_registrar\":\"...\", ...}"   (JSON string)
  timestamp: 1642234567
  plugin_name: "whois-plugin"
  ```

## Example Enrichment Output

After publishing an event with `{"url":"http://example.com"}`, a sample enrichment may contain data keys like:

```
{
  "whois_example_com_registrar": "RESERVED-Internet Assigned Numbers Authority",
  "whois_example_com_created_date": "1995-08-14T04:00:00Z",
  "whois_example_com_expiration_date": "2026-08-13T04:00:00Z",
  "whois_example_com_nameservers": "A.IANA-SERVERS.NET,B.IANA-SERVERS.NET",
  "whois_example_com_raw_snippet": "Domain Name: EXAMPLE.COM\r\n ... (truncated)"
}
```

These keys are flat and prefixed by `whois_<domain>_<field>`. Fields are best-effort and may vary by TLD and WHOIS server response.

## End-to-End Test (Integration)

A helper script is provided to build and verify the plugin end-to-end using Dockerized Redis:

- [`console-ir/tests/test-whois-plugin.sh`](../../tests/test-whois-plugin.sh:1)

This script will:
- Start `redis:7-alpine` as `consoleir-redis` (if not running)
- Build the plugin into `console-ir/bin/whois`
- Launch the plugin
- Publish a test event to `events`
- Dump recent `enrichments` entries (look for `source=whois`)

Run it:
- `bash console-ir/tests/test-whois-plugin.sh`
- If docker requires sudo on your machine: `sudo bash console-ir/tests/test-whois-plugin.sh`

## Operational Notes

- Rate limiting: The plugin uses a simple token bucket to cap WHOIS queries per second (configurable via `--rate-limit-rps`).
- Caching: An in-memory TTL cache reduces repeat WHOIS lookups (configurable via `--cache-ttl`).
- Resilience: Basic retry/backoff around WHOIS lookups. WHOIS servers vary in behavior and formatting.
- Field variability: WHOIS outputs are not strictly standardized. Normalization is best-effort via robust regexes.

## Troubleshooting

- No enrichments:
  - Ensure events are being published to `events` with `event_id` and `raw_json`.
  - Confirm that the `raw_json` contains a domain or URL the parser can extract.
- Redis auth/remote host:
  - Provide a full Redis URL including credentials and DB: `--redis "redis://user:pass@host:6379/0"`
- Docker not running:
  - Start Docker or run Redis locally (`redis-server`) and point the plugin to it.

## Maintenance Pointers

- Domain detection: see [extractDomains()](./main.go:146)
- Enrichment shaping: see [normalizeWhois()](./main.go:237)
- Stream publishing shape: see [`console-ir/plugins/whois/main.go`](./main.go:309) in `publishEnrichment`

