.PHONY: test-load

# Measures what a test server carries, driving it from outside. SCENARIO is one of those in
# sim/load/load.py, or all. Needs the image from make test-server. LOAD_ARGS passes anything else.
SCENARIO ?= all
test-load:
	uv run --quiet --no-project --python 3.13 --with cryptography --with aiohttp \
		python sim/load/load.py $(SCENARIO) --profile $(PROFILE) $(LOAD_ARGS)
