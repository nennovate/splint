.PHONY: test-server test-server-stop

# Starts a host and Postgres in Docker under a small server's limits. PROFILE is small or tiny.
PROFILE ?= small
test-server:
	python3 sim/test-server/server.py start $(PROFILE)

test-server-stop:
	python3 sim/test-server/server.py stop
