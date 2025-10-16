#!/usr/bin/env bash
set -euo pipefail

# Resolve script directory and find the repository root reliably.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Walk up ancestors from the script directory to find the directory that contains console-ir/plugins
REPO_ROOT=""
current="$SCRIPT_DIR"
while [ "$current" != "/" ]; do
  if [ -d "$current/console-ir/plugins" ]; then
    REPO_ROOT="$current"
    break
  fi
  current="$(dirname "$current")"
done

# Fallback to present working directory if we couldn't find the expected layout
if [ -z "$REPO_ROOT" ]; then
  REPO_ROOT="$(pwd)"
fi

CONSOLE_DIR="$REPO_ROOT/console-ir"
REDIS_CONTAINER="consoleir-redis"
PLUGIN_BIN="$CONSOLE_DIR/bin/llm"
PLUGIN_LOG="$CONSOLE_DIR/logs/llm-plugin.log"
CONSUMER_NAME="llm-test"
DRYRUN_JSON="$CONSOLE_DIR/tests/llm-dryrun.json"

DOCKER_CMD="docker"
if ! $DOCKER_CMD info >/dev/null 2>&1; then
  if sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD="sudo docker"
  else
    echo "docker not available or not usable. Install Docker or enable your user to use Docker."
    exit 1
  fi
fi

echo "Working from: $REPO_ROOT"
if [ ! -d "$CONSOLE_DIR" ]; then
  echo "Cannot find console-ir directory at $CONSOLE_DIR"
  exit 1
fi

# 1) Start Redis if not running
if ! $DOCKER_CMD ps --format '{{.Names}}' | grep -w "$REDIS_CONTAINER" >/dev/null 2>&1; then
  echo "Starting Redis container ($REDIS_CONTAINER)..."
  $DOCKER_CMD run -d --name "$REDIS_CONTAINER" -p 6379:6379 redis:7-alpine
else
  echo "Redis container $REDIS_CONTAINER already running"
fi

# 2) Build the LLM plugin inside golang:1.25, running the container as the host user to avoid root-owned files
echo "Building LLM plugin in golang:1.25 container (running as current user)..."
$DOCKER_CMD run --rm \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GOCACHE=/tmp/.cache/go-build \
  -e GOMODCACHE=/workspace/go/pkg/mod \
  -v "$REPO_ROOT":/workspace \
  -w /workspace/console-ir \
  golang:1.25 sh -c 'mkdir -p /tmp/.cache/go-build /workspace/go/pkg/mod && cd /workspace/console-ir && go env -w GOMODCACHE=/workspace/go/pkg/mod && go build -o bin/llm plugins/llm/main.go'
echo "Build attempt complete: $PLUGIN_BIN"

# 3) Ensure the binary is owned by the current user and executable. If not, attempt a sudo fix.
if [ -f "$PLUGIN_BIN" ]; then
  if [ ! -x "$PLUGIN_BIN" ]; then
    echo "Binary exists but is not executable; trying chmod..."
    if chmod +x "$PLUGIN_BIN" 2>/dev/null; then
      echo "chmod succeeded"
    else
      echo "chmod failed; attempting to fix ownership with sudo..."
      if sudo chown "$(id -u):$(id -g)" "$PLUGIN_BIN" && sudo chmod +x "$PLUGIN_BIN"; then
        echo "Ownership and permissions fixed with sudo"
      else
        echo "Failed to fix permissions for $PLUGIN_BIN; please adjust file ownership manually."
        exit 1
      fi
    fi
  fi
else
  echo "Build did not produce $PLUGIN_BIN"
  exit 1
fi

# 4) Write canned dry-run response JSON
mkdir -p "$CONSOLE_DIR/tests"
cat > "$DRYRUN_JSON" <<'JSON'
{"summary":"Suspicious network activity","security_significance":"Potential command-and-control traffic","recommended_actions":["Isolate host","Block destination IP","Collect network packet capture"],"risk_level":"High","confidence":0.82,"threat_type":"C2"}
JSON

# 5) Start LLM plugin (background) in dry-run mode — plugin connects to Redis on localhost:6379
echo "Starting LLM plugin (background, dry-run)..."
mkdir -p "$CONSOLE_DIR/logs"
cd "$CONSOLE_DIR/tests"
"$PLUGIN_BIN" --redis "redis://localhost:6379" --consumer "$CONSUMER_NAME" --provider openai --model gpt-3.5-turbo --dry-run --dry-run-response "$DRYRUN_JSON" > "$PLUGIN_LOG" 2>&1 &
PLUGIN_PID=$!
echo "LLM plugin started with PID $PLUGIN_PID; logs -> $PLUGIN_LOG"
cd "$REPO_ROOT"

# give plugin & redis a moment
sleep 2

# 6) Publish a test OCSF-like event
JSON='{"activity_name":"Network Activity","category_name":"Network","class_name":"Network Activity","time":"2025-01-01T00:00:00Z","severity":"medium","src_endpoint":{"ip":"1.2.3.4"},"dst_endpoint":{"ip":"5.6.7.8"}}'
TS=$(date +%s)

# Prefer the official ingest path (ensures DB event_id alignment for TUI). Fallback to raw XADD if console-ir binary is unavailable.
CONSOLE_BIN="$CONSOLE_DIR/bin/console-ir"
if [ -x "$CONSOLE_BIN" ]; then
  echo "Publishing test event via console-ir ingest (preferred)..."
  printf '%s\n' "$JSON" | "$CONSOLE_BIN" ingest - || {
    echo "Ingest failed; falling back to Redis XADD..."
    $DOCKER_CMD exec -i "$REDIS_CONTAINER" redis-cli XADD events "*" event_id evt_llm_1 event_type ocsf raw_json "$JSON" timestamp "$TS"
  }
else
  echo "console-ir binary not found; publishing test event via Redis XADD..."
  $DOCKER_CMD exec -i "$REDIS_CONTAINER" redis-cli XADD events "*" event_id evt_llm_1 event_type ocsf raw_json "$JSON" timestamp "$TS"
fi

# wait for processing
sleep 3

# 7) Read recent enrichments from Redis
echo ""
echo "Recent entries in enrichments stream (XRANGE):"
$DOCKER_CMD exec -i "$REDIS_CONTAINER" redis-cli XRANGE enrichments - + COUNT 10 || true

echo ""
echo "Tail of plugin log (last 80 lines):"
tail -n 80 "$PLUGIN_LOG" || true

echo ""
echo "If you see enrichment messages with source=llm and data containing keys like 'llm_summary' and 'llm_risk_level', processing worked."
echo "To stop the plugin process you can run: kill $PLUGIN_PID"
echo "To stop and remove Redis container: $DOCKER_CMD rm -f $REDIS_CONTAINER"