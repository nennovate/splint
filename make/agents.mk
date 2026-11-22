.PHONY: agents test-agents trace

# Runs real Claude agents through Splint. This costs model usage, so it isn't part of check.
agents:
	uv run --quiet --no-project --python 3.13 --with claude-agent-sdk python sim/claude_agents.py

# A real agent runtime with its normal tools, memory and files, through what ships in adapters/. It
# needs the claude CLI, logged in, and spends model usage, up to SPLINT_AGENT_BUDGET_USD, so it isn't part of
# check. It runs on this machine unless SPLINT_LIVE_HOSTS names real servers.
test-agents:
	cd adapters/mcp && npm ci --ignore-scripts --silent
	python3 sim/realistic_agents.py

# Shows how a scripted request travels through Splint. No model, so this costs nothing.
trace:
	python3 sim/scripted_run.py
