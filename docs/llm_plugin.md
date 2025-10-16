# LLM Plugin Implementation Summary

## Overview

I have successfully created a new LLM plugin for the Console-IR system with similar structure to the existing GeoIP plugin. The plugin enables users to leverage Large Language Models (OpenAI GPT or Anthropic Claude) for AI-powered security event analysis and enrichment.

## Files Created

### Core Plugin Files
- `plugins/llm/main.go` - Main plugin implementation with full LLM integration
- `plugins/llm/go.mod` - Go module dependencies
- `plugins/llm/README.md` - Comprehensive documentation
- `plugins/llm/prompt_template.txt` - Default prompt template
- `plugins/llm/config_examples.txt` - Configuration examples
- `plugins/llm/incident_response_prompt.txt` - Specialized incident response template
- `plugins/llm/threat_intel_prompt.txt` - Threat intelligence analysis template

### Build System
- `build-plugins.ps1` - PowerShell script for building plugins on Windows
- Updated `Makefile` with `plugin-llm` target

## Key Features Implemented

### 1. Multi-Provider Support
- **OpenAI GPT**: Supports GPT-3.5-turbo, GPT-4, GPT-4-turbo, GPT-4o
- **Anthropic Claude**: Supports Claude-3-sonnet, Claude-3-opus, Claude-3-haiku

### 2. Configurable Settings
- **API Key**: Command line flag or environment variable (`LLM_API_KEY`)
- **Provider**: Choose between `openai` or `claude`
- **Model**: Specify exact model version
- **Temperature**: Control randomness (0.0-2.0)
- **Max Tokens**: Limit response length
- **Stop Words**: Comma-separated list of stop sequences

### 3. Flexible Prompt System
- **Template Files**: Go template syntax with access to full event data
- **Event Field Access**: All OCSF fields available via `.Event.field_name`
- **Multiple Templates**: Different templates for different analysis types
- **Auto-generation**: Creates default template if none exists

### 4. Structured Output Processing
- **JSON Extraction**: Attempts to parse structured JSON from LLM responses
- **Pattern Matching**: Falls back to regex patterns for key information
- **Enrichment Data**: Stores both raw responses and extracted fields

### 5. Redis Stream Integration
- **Event Consumption**: Reads from `events` stream like GeoIP plugin
- **Enrichment Publishing**: Publishes to `enrichments` stream
- **Consumer Groups**: Proper Redis stream consumer group handling
- **Error Resilience**: Continues processing even if individual events fail

## Configuration Examples

### OpenAI Configuration
```bash
.\bin\llm --api-key YOUR_OPENAI_KEY --provider openai --model gpt-3.5-turbo --temperature 0.7
```

### Claude Configuration
```bash
.\bin\llm --api-key YOUR_CLAUDE_KEY --provider claude --model claude-3-sonnet-20240229 --temperature 0.3
```

### Environment Variable
```bash
$env:LLM_API_KEY = "your-key-here"
.\bin\llm --provider openai --model gpt-4
```

## Output Data Structure

The plugin enriches events with the following fields in the `EnrichmentMessage.Data`:

### Always Present
- `llm_raw_response`: Complete LLM response text
- `llm_model`: Model used for analysis
- `llm_provider`: API provider (openai/claude)
- `llm_timestamp`: Analysis timestamp

### Extracted from JSON (when LLM returns structured data)
- `llm_summary`: Brief event summary
- `llm_security_significance`: Security importance
- `llm_risk_level`: Risk assessment
- `llm_confidence`: Confidence score
- `llm_threat_type`: Type of threat identified
- `llm_recommended_actions`: JSON array of recommendations
- `llm_iocs`: Indicators of compromise
- And any other fields the LLM returns in JSON format

### Pattern-Based Extraction (fallback)
- `llm_risk_level`: Extracted via regex if not in JSON
- `llm_confidence`: Confidence score from text
- `llm_threat_type`: Threat type mentioned in text
- `llm_severity`: Severity level
- `llm_recommendation`: First recommendation found

## Prompt Templates

### Default Template
Focuses on general security analysis with structured JSON output including:
- Event summary
- Security significance  
- Risk level assessment
- Recommended actions
- Threat indicators

### Incident Response Template
Specialized for incident response with focus on:
- Immediate threat assessment
- Incident classification
- Containment recommendations
- Investigation priorities
- Escalation requirements

### Threat Intelligence Template
Designed for threat hunting and intelligence analysis:
- IOC extraction (IPs, domains, hashes, etc.)
- MITRE ATT&CK mapping
- Attribution analysis
- Behavioral indicators
- Attack stage identification

## Building and Running

### Build All Plugins
```powershell
.\build-plugins.ps1
```

### Build Specific Plugin
```powershell
.\build-plugins.ps1 -Plugin llm
```

### Run Plugin
```bash
# With OpenAI
.\bin\llm --api-key YOUR_OPENAI_KEY --provider openai --model gpt-3.5-turbo

# With Claude  
.\bin\llm --api-key YOUR_CLAUDE_KEY --provider claude --model claude-3-sonnet-20240229

# With custom template
.\bin\llm --api-key YOUR_KEY --provider openai --prompt-file incident_response_prompt.txt
```

## Architecture Consistency

The LLM plugin follows the same architectural patterns as the GeoIP plugin:

1. **Redis Stream Consumer**: Reads from `events` stream with consumer group
2. **Event Processing**: Parses EventMessage from Redis
3. **Enrichment Logic**: Performs analysis (LLM API calls vs GeoIP lookups)
4. **Data Publishing**: Publishes EnrichmentMessage to `enrichments` stream
5. **Error Handling**: Graceful error handling and logging
6. **Signal Handling**: Proper shutdown on SIGINT/SIGTERM
7. **Configuration**: Command-line flags and environment variables

## Performance Considerations

- **Sequential Processing**: Processes events one at a time to avoid overwhelming LLM APIs
- **Timeout Handling**: 60-second timeout for API calls
- **Rate Limiting**: Natural rate limiting due to API latency
- **Error Recovery**: Continues processing other events if one fails
- **Configurable Batch Size**: Processes fewer events per batch (5 vs 10) due to API latency

## Security Features

- **API Key Protection**: Supports environment variables for secure key storage
- **Input Validation**: Validates all configuration parameters
- **Error Sanitization**: Careful error message handling to avoid key leakage
- **Template Security**: Safe template execution with proper escaping

## Testing Verified

✅ Plugin builds successfully on Windows
✅ Command-line argument parsing works
✅ Both OpenAI and Claude API structures implemented
✅ Template system functional with Go templates
✅ JSON extraction and pattern matching implemented
✅ Redis integration follows established patterns
✅ Error handling and graceful shutdown implemented
✅ PowerShell build system created and tested

The LLM plugin is now ready for use and provides a powerful AI-driven enhancement to the Console-IR security event processing pipeline.
