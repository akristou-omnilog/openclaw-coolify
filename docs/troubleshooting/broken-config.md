---
summary: "How to recover from a broken openclaw.json configuration"
read_when:
  - Container keeps restarting due to config errors
  - You edited openclaw.json manually and broke it
  - Gateway won't start due to invalid configuration
---

# Recovering from Broken Config

If your OpenClaw container won't start due to a corrupted or invalid `openclaw.json` file, you have several recovery options.

## Quick Diagnosis

Check your container logs in Coolify:

```bash
# Look for these error messages:
# - "SyntaxError: Unexpected token in JSON"
# - "Cannot read property 'gateway' of undefined"
# - "Invalid configuration"
# - "⚠️  CRITICAL: Invalid JSON detected"
```

## Recovery Options

### Option 1: Automatic Safe Mode (Easiest)

This regenerates your config automatically while preserving backups.

**Steps:**

1. In Coolify, go to your OpenClaw service
2. Navigate to **Environment Variables**
3. Add: `OPENCLAW_SAFE_MODE=1`
4. Click **Save**
5. Restart the container

**What happens:**
- Bootstrap detects invalid config
- Creates timestamped backup (`.openclaw.json.broken.TIMESTAMP`)
- Attempts to preserve your authentication token
- Generates fresh config
- Container starts successfully

**After recovery:**
- Remove `OPENCLAW_SAFE_MODE=1` from environment variables
- Save and restart one more time
- Your old config is saved as backup for reference

---

### Option 2: Manual Inspection & Editing

Use the config inspector utility to manually fix the config.

**Prerequisites:**
- Docker and docker-compose installed locally
- Access to your server

**Steps:**

```bash
# 1. SSH to your Coolify server
ssh user@your-server

# 2. Navigate to openclaw directory
cd /path/to/openclaw-coolify

# 3. Start inspector container
make config-inspect

# 4. This opens an interactive shell with access to your config
# Inside the inspector:
config-inspector

# 5. Edit the config
nano /data/.openclaw/openclaw.json

# 6. Validate your changes
jq empty /data/.openclaw/openclaw.json

# 7. Exit and restart main container
exit
docker compose -f docker-compose.inspector.yaml down
docker compose up -d
```

**Without Make:**
```bash
docker compose -f docker-compose.inspector.yaml up -d
docker compose -f docker-compose.inspector.yaml exec inspector bash
config-inspector
```

---

### Option 3: Complete Reset (Nuclear Option)

Delete config entirely and let OpenClaw regenerate defaults.

**⚠️  WARNING:** This loses all your settings and generates a new auth token.

**Steps:**

```bash
# Using make:
make config-reset

# Or manually:
docker compose run --rm --no-deps openclaw bash -c 'rm /data/.openclaw/openclaw.json'
docker compose up -d --force-recreate
```

---

## Prevention

### Before Manual Edits

Always backup before editing:

```bash
make config-backup

# Or:
docker compose exec openclaw cp /data/.openclaw/openclaw.json /data/.openclaw/openclaw.json.backup
```

### Use Built-in Commands

Instead of editing JSON directly, use the CLI:

```bash
# Correct way:
docker compose exec openclaw openclaw config set gateway.port 19001

# Avoid:
# Manually editing openclaw.json
```

### Validate After Edits

If you must edit manually, always validate:

```bash
docker compose exec openclaw jq empty /data/.openclaw/openclaw.json
# No output = valid JSON
```

---

## Common Config Errors

### Missing Comma

```json
{
  "gateway": {
    "port": 18789
    "mode": "local"  // ❌ Missing comma after 18789
  }
}
```

**Fix:** Add comma after `18789`:
```json
{
  "gateway": {
    "port": 18789,
    "mode": "local"
  }
}
```

### Trailing Comma

```json
{
  "agents": {
    "list": [
      { "id": "main" },  // ❌ Trailing comma
    ]
  }
}
```

**Fix:** Remove comma after last item:
```json
{
  "agents": {
    "list": [
      { "id": "main" }
    ]
  }
}
```

### Unquoted Keys

```json
{
  gateway: {  // ❌ Should be "gateway"
    "port": 18789
  }
}
```

**Fix:** Quote all keys:
```json
{
  "gateway": {
    "port": 18789
  }
}
```

### Comments

```json
{
  "gateway": {
    // This is a comment  // ❌ JSON doesn't support comments
    "port": 18789
  }
}
```

**Fix:** Remove comments or use a different format for notes.

---

## Automatic Recovery Features

OpenClaw now includes automatic config validation on startup:

1. **JSON Validation** - Checks if config is valid JSON
2. **Structure Validation** - Ensures required sections exist (`.gateway`, `.agents`)
3. **Automatic Backup** - Creates timestamped backups before regeneration
4. **Token Recovery** - Attempts to preserve your auth token from broken config

You'll see these messages in the logs when automatic recovery happens:

```
⚠️  CRITICAL: Invalid JSON detected in /data/.openclaw/openclaw.json
📦 Backup saved to: /data/.openclaw/openclaw.json.broken.1234567890
🔄 Attempting recovery...
🔑 Recovered authentication token from backup
🏥 Generating openclaw.json with Prime Directive...
🔐 Reusing recovered authentication token
```

---

## Helper Commands

Check config status without starting container:

```bash
make config-check
```

Create manual backup:

```bash
make config-backup
```

Open inspector for manual editing:

```bash
make config-inspect
```

Force reset to defaults:

```bash
make config-reset
```

---

## Getting Help

If automatic recovery fails:

1. Check [GitHub Issues](https://github.com/essamamdani/openclaw-coolify/issues)
2. Share your error logs (redact tokens!)
3. Include output from: `make config-check`

## Related

- [OpenClaw Configuration](/docs/cli/config.md)
- [Gateway Configuration](/docs/gateway/configuration.md)
- [Docker Compose Setup](/README.md)
