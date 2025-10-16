#!/bin/bash
../../bin/misp-plugin --dry-run --redis redis://localhost:6379 &
PLUGIN_PID=$!
sleep 5
kill $PLUGIN_PID 2>/dev/null
wait $PLUGIN_PID 2>/dev/null
exit 0
