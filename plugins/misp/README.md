# MISP Plugin for Console-IR

This plugin integrates MISP (Malware Information Sharing Platform) with Console-IR to provide real-time community-driven threat intelligence enrichment for security events.

## Features

- **MISP REST API Integration**: Native support for MISP attributes, events, and galaxy clusters
- **Multi-Observable Support**: Enriches IP addresses, domains, file hashes, URLs, and email addresses
- **Community Intelligence**: Provides event correlation, organization context, and sharing group information
- **Tag Taxonomy**: Processes MISP tags and galaxy clusters for threat actor and malware identification
- **Event Correlation**: Links observables to related MISP events and IOCs
- **Intelligent Caching**: Redis and in-memory caching with configurable TTL
- **Rate Limiting**: Token bucket algorithm to respect MISP API limits
- **TLP Support**: Respects Traffic Light Protocol markings
- **Dry-Run Mode**: Testing mode with mock community intelligence

## Prerequisites

- Go >= 1.21
- Redis server (for event streams and caching)
- MISP platform with API access
- Valid MISP API key with appropriate permissions

## Installation

### Build from Source

```bash
cd plugins/misp
go mod tidy
go build -o ../../bin/misp-plugin
```

### Using Makefile

```bash
# From console-ir root directory
make plugin-misp
```

## Configuration

### Command Line Options

```bash
./bin/misp-plugin --help
```

**Required Parameters:**
- `--misp-url`: MISP platform base URL
- `--api-key`: MISP API authentication key

**Optional Parameters:**
- `--redis`: Redis connection URL (default: redis://localhost:6379)
- `--timeout`: API request timeout (default: 30s)
- `--rate-limit-rps`: API requests per second (default: 10)
- `--cache-ttl`: Cache time-to-live (default: 4h)
- `--days-back`: Days back to search attributes (default: 30)
- `--only-to-ids`: Only include ToIDS attributes (default: true)

### Environment Variables

```bash
export MISP_URL="https://misp.example.com"
export MISP_API_KEY="your-api-key-here"
```

## Usage Examples

### Basic Usage

```bash
./bin/misp-plugin \
  --misp-url https://misp.example.com \
  --api-key YOUR_API_KEY
```

### Production Configuration

```bash
./bin/misp-plugin \
  --misp-url https://misp.company.com \
  --api-key $MISP_API_KEY \
  --rate-limit-rps 15 \
  --cache-ttl 6h \
  --days-back 60 \
  --correlate-events \
  --max-correlations 10 \
  --include-context
```

### Development/Testing

```bash
# Dry-run mode (no API calls)
./bin/misp-plugin --dry-run

# Local MISP instance
./bin/misp-plugin \
  --misp-url http://localhost:8080 \
  --api-key dev-key \
  --verify-tls=false \
  --rate-limit-rps 5
```

## Enrichment Output

The plugin enriches events with the following fields:

### Observable Information
- `misp_{observable}_threat_level`: HIGH/MEDIUM/LOW/UNDEFINED
- `misp_{observable}_to_ids`: Whether marked as indicator (true/false)
- `misp_{observable}_first_seen`: First seen timestamp
- `misp_{observable}_last_seen`: Last seen timestamp

### Community Intelligence
- `misp_{observable}_events`: Comma-separated event titles
- `misp_{observable}_event_count`: Number of related events
- `misp_{observable}_organizations`: Contributing organizations
- `misp_{observable}_categories`: MISP attribute categories
- `misp_{observable}_tags`: MISP tags and classifications
- `misp_{observable}_galaxy_clusters`: Threat actor/malware clusters
- `misp_{observable}_related_iocs`: Related indicators from same events

### Context Information
- `misp_{observable}_context`: Event context and comments
- `misp_{observable}_analysis_levels`: Analysis completion status
- `misp_{observable}_sharing_groups`: Sharing group memberships

### Example Output

```json
{
  "misp_ip_185_220_101_42_threat_level": "HIGH",
  "misp_ip_185_220_101_42_to_ids": "true",
  "misp_ip_185_220_101_42_events": "APT Campaign Infrastructure,Malicious IP Range",
  "misp_ip_185_220_101_42_organizations": "CIRCL,Financial-ISAC",
  "misp_ip_185_220_101_42_tags": "tlp:white,misp-galaxy:threat-actor=\"APT28\"",
  "misp_ip_185_220_101_42_categories": "Network activity,External analysis",
  "misp_ip_185_220_101_42_galaxy_clusters": "APT28,Fancy Bear",
  "misp_ip_185_220_101_42_related_iocs": "malicious.example.com,c2-server.net",
  "misp_ip_185_220_101_42_event_count": "3",
  "misp_ip_185_220_101_42_first_seen": "2023-12-01T08:00:00Z",
  "misp_ip_185_220_101_42_last_seen": "2024-01-01T15:45:00Z"
}
```

## Observable Types

The plugin processes the following observable types from OCSF events:

### IP Addresses
- Extracted from: `src_endpoint.ip`, `dst_endpoint.ip`, `device.ip`
- Includes both public and private IPs (relevant for community intelligence)
- Enriched with: Event context, threat actors, campaign information

### Domain Names
- Extracted from: `src_endpoint.hostname`, `dst_endpoint.hostname`, `url`
- Enriched with: DNS-based threats, phishing campaigns, C2 infrastructure

### File Hashes
- Extracted from: `file.hashes.*`, `process.file.hashes.*`
- Supports: MD5, SHA1, SHA256, SHA512
- Enriched with: Malware families, threat campaigns, attribution

### URLs
- Extracted from: `url`, `http_request.url`
- Enriched with: Phishing campaigns, malicious hosting, C2 infrastructure

### Email Addresses
- Extracted from: `actor.user.email_addr`, `user.email_addr`
- Enriched with: Phishing campaigns, threat actor attribution

## Performance Considerations

### Rate Limiting
- Default: 10 requests/second with burst of 20
- Configurable via `--rate-limit-rps` and `--burst-limit`
- Automatic backoff on 429 responses

### Caching
- **Redis Cache**: Primary cache for production environments
- **Memory Cache**: Fallback cache with LRU eviction
- **Default TTL**: 4 hours (configurable)
- **Cache Hit Ratio**: Typically >85% in production

### Resource Usage
- **Memory**: ~75-150MB under normal load
- **CPU**: Low impact with proper rate limiting
- **Network**: Depends on observable volume and cache efficiency

## Error Handling

The plugin implements comprehensive error handling:

- **Authentication Errors**: Clear API key validation messages
- **Network Errors**: Exponential backoff retry logic
- **Rate Limiting**: Automatic waiting and retry
- **Invalid Responses**: Graceful degradation
- **Cache Failures**: Automatic fallback between cache types

## Security Considerations

### API Key Security
- Store keys in environment variables
- Use dedicated API users in MISP
- Implement key rotation procedures
- Respect organization access controls

### Data Handling
- Respect TLP (Traffic Light Protocol) markings
- Filter sensitive data from logs
- Implement data retention policies
- Handle personal data appropriately

### Network Security
- TLS certificate validation (configurable)
- Support for self-signed certificates in development
- Network timeout protection

## Monitoring

### Metrics Available
- Events processed
- Enrichments added
- Attributes found
- Events correlated
- Cache hit/miss ratios
- API call success/error rates
- Average processing time

### Logging
- Structured logging with levels: DEBUG, INFO, WARN, ERROR
- Request/response logging for troubleshooting
- Performance metrics logging
- Community intelligence statistics

## Troubleshooting

### Common Issues

**Connection Errors**
```bash
# Test MISP connectivity
curl -H "Authorization: YOUR_API_KEY" https://misp.example.com/servers/getVersion
```

**Authentication Errors**
```bash
# Validate API key
curl -H "Authorization: YOUR_API_KEY" https://misp.example.com/users/view/me
```

**Rate Limiting**
```bash
# Reduce request rate
./bin/misp-plugin --rate-limit-rps 5
```

**Cache Issues**
```bash
# Disable Redis cache temporarily
./bin/misp-plugin --use-redis-cache=false
```

**No Enrichments**
```bash
# Include more data sources
./bin/misp-plugin --only-to-ids=false --days-back 90
```

### Debug Mode

```bash
./bin/misp-plugin --log-level debug --dry-run
```

## TLP (Traffic Light Protocol) Support

The plugin respects TLP markings:
- **TLP:RED**: Not processed (organization internal only)
- **TLP:AMBER**: Limited sharing (handled with care)
- **TLP:GREEN**: Community sharing (normal processing)
- **TLP:WHITE**: Public sharing (normal processing)

## Development

### Running Tests

```bash
cd plugins/misp
go test -v ./...
```

### Integration Testing

```bash
# Start mock MISP server
go test -run TestMockServer

# Test with real MISP (requires credentials)
MISP_URL=https://misp.example.com MISP_API_KEY=key go test -run TestIntegration
```

### Adding New Observable Types

1. Add extraction logic in `extractObservables()`
2. Add validation in `isValid*()` functions
3. Update configuration flags
4. Add test cases
5. Update documentation

## MISP-Specific Features

### Event Correlation
- Links observables to parent MISP events
- Extracts related IOCs from same events
- Provides event context and analysis status

### Galaxy Clusters
- Processes threat actor galaxies
- Handles malware family classifications
- Extracts MITRE ATT&CK mappings from galaxies

### Community Context
- Organization attribution
- Sharing group memberships
- Community validation levels

## Contributing

1. Follow existing code patterns
2. Add comprehensive tests
3. Update documentation
4. Test with real MISP instance
5. Respect community sharing guidelines

## License

Same as Console-IR main project (AGPLv3)

## Support

- GitHub Issues: https://github.com/ashfaaq98/console-ir/issues
- MISP Documentation: https://www.misp-project.org/documentation/
- MISP API Documentation: https://www.misp-project.org/openapi/