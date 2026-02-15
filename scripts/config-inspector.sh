#!/usr/bin/env bash
# config-inspector.sh - Interactive config repair utility

CONFIG_FILE="${OPENCLAW_STATE_DIR:-/data/.openclaw}/openclaw.json"

echo "=========================================="
echo "OpenClaw Config Inspector"
echo "=========================================="
echo ""

if [ ! -f "$CONFIG_FILE" ]; then
  echo "❌ Config file not found at: $CONFIG_FILE"
  echo ""
  echo "This could mean:"
  echo "  1. Fresh installation (normal)"
  echo "  2. Volume not mounted correctly"
  echo ""
  exit 1
fi

echo "📍 Config location: $CONFIG_FILE"
echo ""

# Check if valid JSON
if jq empty "$CONFIG_FILE" 2>/dev/null; then
  echo "✅ Config is valid JSON"
  echo ""
  echo "Config summary:"
  echo "  Gateway port: $(jq -r '.gateway.port // "not set"' "$CONFIG_FILE")"
  echo "  Gateway mode: $(jq -r '.gateway.mode // "not set"' "$CONFIG_FILE")"
  echo "  Agents count: $(jq -r '.agents.list | length' "$CONFIG_FILE" 2>/dev/null || echo "0")"
  echo "  Auth token: $(jq -r '.gateway.auth.token[:8] // "not set"' "$CONFIG_FILE")..."
else
  echo "❌ Config contains INVALID JSON"
  echo ""
  echo "Showing syntax error:"
  jq empty "$CONFIG_FILE" 2>&1 | head -10
fi

echo ""
echo "=========================================="
echo "Available Actions:"
echo "=========================================="
echo "1. View full config:     cat $CONFIG_FILE"
echo "2. Edit config:          nano $CONFIG_FILE"
echo "3. Validate JSON:        jq empty $CONFIG_FILE"
echo "4. Backup config:        cp $CONFIG_FILE $CONFIG_FILE.backup"
echo "5. Delete config:        rm $CONFIG_FILE"
echo "6. View backups:         ls -lh ${CONFIG_FILE}.* 2>/dev/null"
echo "7. Pretty print:         jq . $CONFIG_FILE"
echo ""
echo "To execute commands, you can run them directly in this shell."
echo ""
