.PHONY: test-adapter

# Runs what's in adapters/ against real Signets, so it also needs node, curl and jq.
test-adapter:
	cd adapters/mcp && npm ci --ignore-scripts --silent && npx --no-install tsc && node --test test/*.ts
	python3 sim/adapter.py
