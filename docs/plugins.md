# Plugin Development

Console-IR supports two plugin types:
- Internal Go plugins (loaded in-process)
- External standalone executables (language-agnostic) communicating via Redis Streams

External plugin contract (JSON)
Input (events stream):
```json
{
  "event_id": "evt_1234567890",
  "event_type": "network",
  "raw_json": "{...}",
  "timestamp": 1642234567
}
```

Output (enrichments stream):
```json
{
  "event_id": "evt_1234567890",
  "source": "geoip",
  "type": "location",
  "data": { "country": "United States", "city": "San Francisco" },
  "timestamp": 1642234567,
  "plugin_name": "geoip-plugin"
}
```

Example (overview)
- Create a Redis consumer group for `events`.
- Read messages with XREADGROUP.
- Publish enrichments to `enrichments` stream and XACK the original.

Registration (config)
```yaml
plugins:
  external:
    - name: "my-plugin"
      command: "./plugins/my-plugin"
      enabled: true
      env:
        - "API_KEY=${MY_PLUGIN_API_KEY}"
```

In-process (core) plugins — recommended
- These run inside the binary via the enrichment queue, with no Redis or subprocess.
- GeoIP and WHOIS ship this way; see `internal/enrich/geoip` and `internal/enrich/whois`.
- To add one: implement the `CorePlugin` interface (`internal/plugins/interface.go`) —
  `Process(ctx, event) ([]store.Enrichment, error)` plus lifecycle methods — and register
  it in `cmd/enrich.go` with `pm.GetRegistry().RegisterCorePlugin(...)`.
- Test with a `:memory:` store and a hermetic event; no external services required.

External plugins — for distributed / threat-intel integrations
- Standalone executables (any language) that consume/publish over Redis Streams.
- Used by the MISP, OpenCTI, and IntelOwl integrations under `plugins/`.
- These need a running Redis. Start one with:
  `docker run -d --name console-ir-redis -p 6379:6379 redis`
- Then run the integration tests: `make test-integration`.