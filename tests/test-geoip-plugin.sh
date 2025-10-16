#!/usr/bin/env bash
set -euo pipefail

# Resolve script directory and find the repository root reliably.
# This lets the script be executed from inside console-ir/tests or from the repo root.
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
PLUGIN_BIN="$CONSOLE_DIR/bin/geoip"
PLUGIN_LOG="$CONSOLE_DIR/logs/geoip-plugin.log"
CONSUMER_NAME="geoip-test"

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

# 2) Build the geoip plugin inside golang:1.25, running the container as the host user to avoid root-owned files
echo "Building geoip plugin in golang:1.25 container (running as current user)..."
$DOCKER_CMD run --rm \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GOCACHE=/tmp/.cache/go-build \
  -e GOMODCACHE=/workspace/go/pkg/mod \
  -v "$REPO_ROOT":/workspace \
  -w /workspace/console-ir \
  golang:1.25 sh -c 'mkdir -p /tmp/.cache/go-build /workspace/go/pkg/mod && cd /workspace/console-ir && go env -w GOMODCACHE=/workspace/go/pkg/mod && go build -o bin/geoip plugins/geoip/main.go'
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

# 4) Start geoip plugin (background) — plugin connects to Redis on localhost:6379
echo "Starting geoip plugin (background)..."
# Ensure logs directory exists and run from tests directory
mkdir -p "$CONSOLE_DIR/logs"
cd "$CONSOLE_DIR/tests"
"$PLUGIN_BIN" --redis "redis://localhost:6379" --consumer "$CONSUMER_NAME" > "$PLUGIN_LOG" 2>&1 &
PLUGIN_PID=$!
echo "GeoIP plugin started with PID $PLUGIN_PID; logs -> $PLUGIN_LOG"
cd "$REPO_ROOT"

# give plugin & redis a moment
sleep 2

# 5) Publish a test event with a public and a private IP
JSON='{"src_endpoint":{"ip":"8.8.8.8"},"dst_endpoint":{"ip":"1.1.1.1"},"device":{"ip":"10.0.0.5"}}'
TS=$(date +%s)
echo "Publishing test event to Redis (events stream)..."
# Quote the '*' so the host shell doesn't expand it to filenames
$DOCKER_CMD exec -i "$REDIS_CONTAINER" redis-cli XADD events "*" event_id evt_demo_1 event_type network raw_json "$JSON" timestamp "$TS"

# wait for processing
sleep 2

# 6) Read recent enrichments from Redis
echo ""
echo "Recent entries in enrichments stream (XRANGE):"
$DOCKER_CMD exec -i "$REDIS_CONTAINER" redis-cli XRANGE enrichments - + COUNT 10 || true

echo ""
echo "Tail of plugin log (last 80 lines):"
tail -n 80 "$PLUGIN_LOG" || true

echo ""
echo "If you see enrichment messages with source=geoip and data containing keys like 'geoip_8_8_8_8_country', processing worked."
echo "To stop the plugin process you can run: kill $PLUGIN_PID"
echo "To stop and remove Redis container: $DOCKER_CMD rm -f $REDIS_CONTAINER"