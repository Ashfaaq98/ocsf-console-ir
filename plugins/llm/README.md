# LLM Plugin

The LLM plugin enriches security events using Large Language Models (OpenAI GPT or Anthropic Claude) to provide AI-powered analysis and insights.

## Features

- **Multi-Provider Support**: Works with OpenAI GPT models and Anthropic Claude
- **Customizable Prompts**: Uses template files for flexible prompt customization
- **Structured Analysis**: Attempts to extract structured data from LLM responses
- **Configurable Parameters**: Supports temperature, max tokens, and stop words
- **Pattern Extraction**: Falls back to regex patterns when JSON parsing fails

## Configuration

### Required Parameters

- `--api-key`: Your OpenAI or Claude API key (can also use `LLM_API_KEY` environment variable)

### Optional Parameters

- `--redis`: Redis connection URL (default: `redis://localhost:6379`)
- `--consumer`: Consumer name for Redis streams (default: `llm-plugin`)
- `--provider`: LLM provider - `openai` or `claude` (default: `openai`)
- `--model`: Model to use (default: `gpt-3.5-turbo`)
- `--temperature`: Temperature for generation 0.0-2.0 (default: `0.7`)
- `--max-tokens`: Maximum tokens in response (default: `500`)
- `--stop-words`: Comma-separated stop words
- `--prompt-file`: Path to prompt template file (default: `./prompt_template.txt`)

### Supported Models

#### OpenAI
- `gpt-3.5-turbo`
- `gpt-4`
- `gpt-4-turbo`
- `gpt-4o`

#### Claude
- `claude-3-sonnet-20240229`
- `claude-3-opus-20240229`
- `claude-3-haiku-20240307`

## Usage

### Basic Usage with OpenAI

```bash
./llm --api-key YOUR_OPENAI_API_KEY --provider openai --model gpt-3.5-turbo
```

### Usage with Claude

```bash
./llm --api-key YOUR_CLAUDE_API_KEY --provider claude --model claude-3-sonnet-20240229
```

### Advanced Configuration

```bash
./llm \
  --api-key YOUR_API_KEY \
  --provider openai \
  --model gpt-4 \
  --temperature 0.3 \
  --max-tokens 1000 \
  --stop-words "END,STOP" \
  --prompt-file custom_prompt.txt
```

### Environment Variables

You can set the API key using an environment variable:

```bash
export LLM_API_KEY="your-api-key-here"
./llm --provider openai
```

## Prompt Templates

The plugin uses Go template syntax to generate prompts. The template has access to the event data through the `.Event` object.

### Template Variables

- `.Event`: The complete event object with all fields
- `.Event.activity_name`: Event activity name
- `.Event.src_endpoint.ip`: Source IP address
- `.Event.dst_endpoint.ip`: Destination IP address
- `.Event.device.name`: Device name
- `.Event.actor.user.name`: User name
- And all other OCSF event fields...

### Example Template

```go
Analyze this security event:

Event: {{.Event.activity_name}}
{{if .Event.src_endpoint}}Source: {{.Event.src_endpoint.ip}}{{end}}
{{if .Event.dst_endpoint}}Destination: {{.Event.dst_endpoint.ip}}{{end}}

Provide analysis in JSON format:
{
  "summary": "Brief description",
  "risk_level": "Low|Medium|High|Critical",
  "recommendations": ["action1", "action2"]
}
```

## Output

The plugin enriches events with the following data fields:

- `llm_raw_response`: Complete LLM response
- `llm_model`: Model used for analysis
- `llm_provider`: API provider used
- `llm_timestamp`: When the analysis was performed

### Structured Fields (extracted from JSON responses)

- `llm_summary`: Brief event summary
- `llm_security_significance`: Security importance
- `llm_risk_level`: Risk assessment
- `llm_confidence`: Confidence score
- `llm_threat_type`: Type of threat identified
- `llm_recommended_actions`: JSON array of recommendations

### Pattern-Based Fields (extracted via regex)

- `llm_risk_level`: Risk level if found in text
- `llm_confidence`: Confidence score if found
- `llm_threat_type`: Threat type if mentioned
- `llm_severity`: Severity level
- `llm_recommendation`: First recommendation found

## Building

From the plugin directory:

```bash
go build -o ../../bin/llm .
```

Or using the Makefile from the project root:

```bash
make build-plugins
```

## API Costs

Be aware that this plugin makes API calls to external LLM services which may incur costs:

- **OpenAI**: Charges per token (input + output)
- **Claude**: Charges per token (input + output)

Monitor your usage and set appropriate rate limits if needed.

## Error Handling

The plugin includes robust error handling for:

- API failures and retries
- Malformed responses
- Network timeouts
- Template parsing errors
- JSON extraction failures

Events that fail LLM processing are logged but don't stop the plugin from processing other events.

## Performance Considerations

- LLM API calls have latency (1-10 seconds typically)
- The plugin processes events sequentially to avoid overwhelming the API
- Consider using shorter prompts and lower max_tokens for faster responses
- Monitor API rate limits and quotas

## Security Notes

- Store API keys securely using environment variables
- Consider network security when making external API calls
- Be mindful of data privacy when sending events to external services
- Review prompt templates to avoid sending sensitive information


## New Features and Testability

This plugin now supports:
- Dry-run mode to test without real API calls.
- Base URL overrides for OpenAI and Anthropic (useful for mocking).
- Basic retry with backoff on transient HTTP errors (429/5xx).
- Pending message reclaim (XAUTOCLAIM) so crashed/unacked events get reprocessed.

### New Flags
- `--dry-run` Return canned LLM response without any network calls.
- `--dry-run-response` Path to a file containing the canned LLM response (JSON or text). If omitted, a default JSON is used.
- `--openai-base-url` Override the OpenAI API base URL (default: https://api.openai.com).
- `--anthropic-base-url` Override the Anthropic API base URL (default: https://api.anthropic.com).
- `--retries` Number of retry attempts for transient errors (default: 2).

API key behavior:
- In non-dry-run mode, the API key is required via `--api-key` or `LLM_API_KEY`.
- In dry-run mode, no API key is required.

### Examples

Dry-run, no network:
```bash
./llm --redis redis://localhost:6379 \
  --consumer llm-test \
  --provider openai \
  --model gpt-3.5-turbo \
  --dry-run \
  --dry-run-response ./tests/llm-dryrun.json
```

OpenAI with retries and base URL override:
```bash
./llm --api-key "$LLM_API_KEY" \
  --provider openai \
  --model gpt-4o \
  --openai-base-url https://api.openai.com \
  --retries 3
```

Anthropic with retries:
```bash
./llm --api-key "$LLM_API_KEY" \
  --provider claude \
  --model claude-3-sonnet-20240229 \
  --retries 3
```

### End-to-End Dry-Run Test Script

A test script is available at [tests/test-llm-plugin.sh](../../tests/test-llm-plugin.sh). It:
- Starts Redis in Docker if needed.
- Builds the LLM plugin.
- Writes a canned JSON response file for dry-run mode.
- Runs the plugin with `--dry-run`.
- Publishes a sample event to the `events` stream.
- Prints recent entries from the `enrichments` stream and tails the plugin log.

Run it:
```bash
bash console-ir/tests/test-llm-plugin.sh
```

Expected outcome:
- Enrichment entries on `enrichments` stream with `source=llm`.
- Data includes fields like `llm_summary`, `llm_risk_level`, `llm_recommended_actions`.

### Viewing Enrichments in the TUI

To see enrichments appear inside the TUI:
1) Start the Console-IR server (TUI + background services):
```bash
./bin/console-ir serve
```
- The server runs an enrichment processor that reads from the `enrichments` stream and persists data into SQLite (see [cmd/serve.go](../../cmd/serve.go)).
- It also runs a folder ingestor watching `./data/incoming` by default; dropping JSON/JSONL there will create events.

2) In another terminal, run the LLM plugin in dry-run mode:
```bash
./console-ir/bin/llm --redis redis://localhost:6379 --consumer llm-tui \
  --provider openai --model gpt-3.5-turbo --dry-run
```

3) Ingest an example event either by:
- Using the `ingest` command:
```bash
./bin/console-ir ingest console-ir/data/incoming/test-event.jsonl
```
- Or dropping a JSON line into `console-ir/data/incoming/*.jsonl` while the server is running (folder watcher enabled).

4) In the TUI:
- Select “ALL EVENTS” or a case if you assigned events.
- Select an event and check the Event Details pane. You should now see an “Enrichments” section listing `llm_*` keys.

Troubleshooting:
- Verify the plugin logs at `./logs/llm-plugin.log`.
- Ensure Redis is available on `redis://localhost:6379`.
- Make sure the server is running so enrichments are applied to the DB.
