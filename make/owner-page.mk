.PHONY: test-owner-page

# The owner page Splint on the computer serves, in a real browser, against real Signets and a real
# host. It needs Docker, Chrome and node.
test-owner-page:
	cd adapters/mcp && npm ci --ignore-scripts --silent && npx --no-install tsc -p ../../packages/splint/src/page/tsconfig.json
	cd adapters/mcp && npx --no-install tsc -p ../../packages/host/src/guest/tsconfig.json
	cd adapters/mcp && npx --no-install tsc -p ../../packages/splint/src/page/web/tsconfig.json
	node packages/splint/src/page/web/keys_test.mjs
	python3 sim/owner_page.py
	python3 sim/owner_controls.py
	python3 sim/owner_page_here.py
	python3 sim/guest_link.py
