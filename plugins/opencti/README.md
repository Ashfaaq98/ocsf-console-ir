# OpenCTI Plugin for Console-IR

This plugin integrates OpenCTI threat intelligence platform with Console-IR to provide real-time threat intelligence enrichment for security events.

## Features

- **STIX 2.1 Integration**: Native support for STIX cyber observables and threat intelligence
- **Multi-Observable Support**: Enriches IP addresses, domains, file hashes, and URLs
- **Threat Intelligence**: Provides threat actors, campaigns, malware, attack patterns, and indicators
- **MITRE ATT&CK Mapping**: Maps observables to MITRE ATT&CK techniques
- **Intelligent Caching**: Redis and in-memory caching with configurable TTL
- **Rate Limiting**: Token bucket algorithm to respect OpenCTI API limits
- **Confidence Filtering**: Configurable minimum confidence thresholds
- **Dry-Run Mode**: Testing mode with mock threat intelligence

## Prerequisites

- Go >= 1.21
- Redis server (for event streams and caching)
- OpenCTI platform with API access
- Valid OpenCTI API token

## Installation

### Build from Source

```bash
cd plugins/opencti
go mod tidy
go build -o ../../bin/opencti-plugin
```

### Using Makefile

```bash
# From console-ir root directory
make plugin-opencti
```

## Configuration

### Command Line Options

```bash
./bin/opencti-plugin --help
```

**Required Parameters:**
- `--opencti-url`: OpenCTI platform base URL
- `--token`: OpenCTI API authentication token

**Optional Parameters:**
- `--redis`: Redis connection URL (default: redis://localhost:6379)
- `--timeout`: API request timeout (default: 30s)
- `--rate-limit-rps`: API requests per second (default: 5)
- `--cache-ttl`: Cache time-to-live (default: 2h)
- `--min-confidence`: Minimum confidence threshold (default: 50)

### Environment Variables

```bash
export OPENCTI_URL="https://opencti.example.com"
export OPENCTI_TOKEN="your-api-token-here"
```

## Usage Examples

### Basic Usage

```bash
./bin/opencti-plugin \
  --opencti-url https://opencti.example.com \
  --token YOUR_API_TOKEN
```

### Production Configuration

```bash
./bin/opencti-plugin \
  --opencti-url https://opencti.company.com \
  --token $OPENCTI_TOKEN \
  --rate-limit-rps 10 \
  --cache-ttl 4h \
  --min-confidence 70 \
  --include-related \
  --max-relations 5
```

### Development/Testing

```bash
# Dry-run mode (no API calls)
./bin/opencti-plugin --dry-run

# Local OpenCTI instance
./bin/opencti-plugin \
  --opencti-url http://localhost:8080 \
  --token dev-token \
  --rate-limit-rps 2
```

## Enrichment Output

The plugin enriches events with the following fields:

### Observable Information
- `opencti_{observable}_confidence`: Confidence score (0-100)
- `opencti_{observable}_threat_level`: CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL
- `opencti_{observable}_first_seen`: First seen timestamp
- `opencti_{observable}_last_seen`: Last seen timestamp

### Threat Intelligence
- `opencti_{observable}_threat_actors`: Comma-separated threat actor names
- `opencti_{observable}_campaigns`: Associated campaign names
- `opencti_{observable}_malware`: Related malware families
- `opencti_{observable}_attack_patterns`: MITRE ATT&CK technique names
- `opencti_{observable}_mitre_techniques`: MITRE ATT&CK technique IDs
- `opencti_{observable}_indicators`: Associated indicator names
- `opencti_{observable}_relationships`: Relationship summary

### Example Output

```json
{
  "opencti_ip_185_220_101_42_confidence": "85",
  "opencti_ip_185_220_101_42_threat_level": "HIGH",
  "opencti_ip_185_220_101_42_threat_actors": "APT28,Fancy Bear",
  "opencti_ip_185_220_101_42_campaigns": "Operation Ghost Stories",
  "opencti_ip_185_220_101_42_mitre_techniques": "T1071.001,T1573.002",
  "opencti_ip_185_220_101_42_indicators": "Malicious IP Range,C2 Infrastructure",
  "opencti_ip_185_220_101_42_first_seen": "2023-11-20T10:30:00Z",
  "opencti_ip_185_220_101_42_last_seen": "2024-01-01T15:45:00Z"
}
```

## Observable Types

The plugin processes the following observable types from OCSF events:

### IP Addresses
- Extracted from: `src_endpoint.ip`, `dst_endpoint.ip`, `device.ip`
- Private and loopback IPs are excluded
- Enriched with: Threat actors, campaigns, malware, geopolitical context

### Domain Names
- Extracted from: `src_endpoint.hostname`, `dst_endpoint.hostname`, `url`
- Enriched with: DNS-based threats, phishing campaigns, C2 infrastructure

### File Hashes
- Extracted from: `file.hashes.*`, `process.file.hashes.*`
- Supports: MD5, SHA1, SHA256, SHA512
- Enriched with: Malware families, threat actors, attack patterns

### URLs (Optional)
- Extracted from: `url`, `http_request.url`
- Enriched with: Phishing campaigns, malicious hosting, C2 infrastructure

## Performance Considerations

### Rate Limiting
- Default: 5 requests/second with burst of 10
- Configurable via `--rate-limit-rps` and `--burst-limit`
- Automatic backoff on 429 responses

### Caching
- **Redis Cache**: Primary cache for production environments
- **Memory Cache**: Fallback cache with LRU eviction
- **Default TTL**: 2 hours (configurable)
- **Cache Hit Ratio**: Typically >80% in production

### Resource Usage
- **Memory**: ~50-100MB under normal load
- **CPU**: Low impact with proper rate limiting
- **Network**: Depends on observable volume and cache efficiency

## Error Handling

The plugin implements comprehensive error handling:

- **Authentication Errors**: Clear token validation messages
- **Network Errors**: Exponential backoff retry logic
- **Rate Limiting**: Automatic waiting and retry
- **Invalid Responses**: Graceful degradation
- **Cache Failures**: Automatic fallback between cache types

## Monitoring

### Metrics Available
- Events processed
- Enrichments added
- Cache hit/miss ratios
- API call success/error rates
- Average processing time

### Logging
- Structured logging with levels: DEBUG, INFO, WARN, ERROR
- Request/response logging for troubleshooting
- Performance metrics logging

## Security Considerations

### Token Security
- Store tokens in environment variables
- Use dedicated service accounts in OpenCTI
- Implement token rotation procedures

### Network Security
- Use HTTPS for OpenCTI communication
- Validate TLS certificates
- Consider network segmentation

### Data Handling
- No sensitive data logged in production
- Configurable confidence thresholds
- Respect data retention policies

## Troubleshooting

### Common Issues

**Connection Errors**
```bash
# Test OpenCTI connectivity
curl -H "Authorization: Bearer $TOKEN" https://opencti.example.com/api/me
```

**Rate Limiting**
```bash
# Reduce request rate
./bin/opencti-plugin --rate-limit-rps 2
```

**Cache Issues**
```bash
# Disable Redis cache temporarily
./bin/opencti-plugin --use-redis-cache=false
```

**No Enrichments**
```bash
# Lower confidence threshold
./bin/opencti-plugin --min-confidence 30
```

### Debug Mode

```bash
./bin/opencti-plugin --log-level debug --dry-run
```

## Development

### Running Tests

```bash
cd plugins/opencti
go test -v ./...
```

### Integration Testing

```bash
# Start mock OpenCTI server
go test -run TestMockServer

# Test with real OpenCTI (requires credentials)
OPENCTI_URL=https://demo.opencti.io OPENCTI_TOKEN=token go test -run TestIntegration
```

### Adding New Observable Types

1. Add extraction logic in `extractObservables()`
2. Add validation in `isValid*()` functions
3. Update configuration flags
4. Add test cases

## Contributing

1. Follow existing code patterns
2. Add comprehensive tests
3. Update documentation
4. Test with real OpenCTI instance

## License

Same as Console-IR main project (AGPLv3)

## Support

- GitHub Issues: https://github.com/ashfaaq98/console-ir/issues
- OpenCTI Documentation: https://docs.opencti.io/
- STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/