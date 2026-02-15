.PHONY: help config-check config-inspect config-reset config-backup

help:
	@echo "OpenClaw Config Recovery Commands"
	@echo ""
	@echo "  make config-check      - Validate config without starting container"
	@echo "  make config-inspect    - Start inspector container for manual editing"
	@echo "  make config-reset      - Reset config to defaults (SAFE MODE)"
	@echo "  make config-backup     - Backup current config"
	@echo ""

config-check:
	@echo "Checking config file..."
	@docker compose run --rm --no-deps openclaw bash -c '\
		CONFIG="/data/.openclaw/openclaw.json"; \
		if [ -f "$$CONFIG" ]; then \
			if jq empty "$$CONFIG" 2>/dev/null; then \
				echo "✅ Config is valid JSON"; \
				jq . "$$CONFIG" | head -20; \
			else \
				echo "❌ Config has invalid JSON:"; \
				jq empty "$$CONFIG" 2>&1; \
			fi \
		else \
			echo "ℹ️  Config file does not exist (will be created on first run)"; \
		fi'

config-inspect:
	@echo "Starting config inspector container..."
	@echo "Once started, run:"
	@echo "  docker compose -f docker-compose.inspector.yaml exec inspector bash"
	@echo "Then use: config-inspector"
	@docker compose -f docker-compose.inspector.yaml up -d
	@sleep 3
	@docker compose -f docker-compose.inspector.yaml exec inspector config-inspector

config-reset:
	@echo "⚠️  WARNING: This will reset your config to defaults!"
	@echo "Your authentication token will be regenerated."
	@echo ""
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Creating backup..."; \
		docker compose run --rm --no-deps openclaw bash -c '\
			CONFIG="/data/.openclaw/openclaw.json"; \
			if [ -f "$$CONFIG" ]; then \
				cp "$$CONFIG" "$$CONFIG.manual-backup.$$(date +%s)"; \
				echo "✅ Backup created"; \
			fi'; \
		echo "Setting SAFE MODE and restarting..."; \
		OPENCLAW_SAFE_MODE=1 docker compose up -d --force-recreate; \
		echo "✅ Container restarted in safe mode"; \
		echo "⚠️  Remember to remove OPENCLAW_SAFE_MODE from .env after recovery"; \
	else \
		echo "Cancelled."; \
	fi

config-backup:
	@echo "Creating config backup..."
	@docker compose run --rm --no-deps openclaw bash -c '\
		CONFIG="/data/.openclaw/openclaw.json"; \
		if [ -f "$$CONFIG" ]; then \
			BACKUP="$$CONFIG.manual-backup.$$(date +%s)"; \
			cp "$$CONFIG" "$$BACKUP"; \
			echo "✅ Backup created: $$BACKUP"; \
		else \
			echo "❌ No config file found"; \
		fi'
