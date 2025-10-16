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

Internal plugins
- Implement the plugin interface in `internal/plugins` and register in the application.
- Use existing examples in `internal/plugins` as a starting point.

Testing plugins
- Use a local Redis instance (docker-compose) and integration tests.
- Example: `make test-integration` (requires Redis)