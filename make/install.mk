.PHONY: install test-install

# Builds what ships and puts it in ~/.splint, so nothing depends on this clone afterwards.
PROFILE ?= release
BUILT = $${CARGO_TARGET_DIR:-$(CURDIR)/packages/target}/$(if $(filter dev,$(PROFILE)),debug,$(PROFILE))
SPLINT_HOME = $(HOME)/.splint
install:
	cd packages && cargo build --quiet --locked --profile $(PROFILE) -p splint -p host -p signet -p owner-key
	@install -d -m 700 "$(SPLINT_HOME)" "$(SPLINT_HOME)/bin"
	@install -m 755 "$(BUILT)/splint" "$(SPLINT_HOME)/bin/splint"
	@install -m 755 "$(BUILT)/host" "$(SPLINT_HOME)/bin/splint-host"
	@install -m 755 "$(BUILT)/signet" "$(SPLINT_HOME)/bin/splint-signet"
	@install -m 755 "$(BUILT)/owner-key" "$(SPLINT_HOME)/bin/splint-owner-key"
	@rm -rf "$(SPLINT_HOME)/adapters" "$(SPLINT_HOME)/schemas" "$(SPLINT_HOME)/examples"
	@install -d "$(SPLINT_HOME)/adapters/mcp/src" "$(SPLINT_HOME)/adapters/http" "$(SPLINT_HOME)/examples"
	@install -m 644 adapters/mcp/package.json adapters/mcp/connect.txt "$(SPLINT_HOME)/adapters/mcp"
	@install -m 644 adapters/mcp/src/*.ts "$(SPLINT_HOME)/adapters/mcp/src"
	@install -m 755 adapters/http/*.sh "$(SPLINT_HOME)/adapters/http"
	@install -m 644 adapters/http/connect.txt "$(SPLINT_HOME)/adapters/http"
	@# Examples an agent can propose from. Nothing reads them as types: two agents agree their own.
	@install -m 644 spec/schemas/*.json "$(SPLINT_HOME)/examples"
	@echo "Installed into $(SPLINT_HOME). Add $(SPLINT_HOME)/bin to your PATH."

# Follows docs/getting-started.md as written, from clean homes, with an agent that's only curl. It
# needs Docker, curl, jq and node. With SPLINT_LIVE_HOSTS it uses those servers instead of Docker.
test-install:
	python3 sim/install.py
	python3 sim/agent_signup.py
	python3 sim/agent_join.py
	python3 sim/proxied_agents.py
	python3 sim/agreed_time.py
	python3 sim/join_with_code.py
	python3 sim/owner_api.py
	python3 sim/owner_device.py
	python3 sim/owner_mail_sealed.py
	python3 sim/direct_access.py
	python3 sim/profiles.py
	python3 sim/rules_at_host.py
	python3 sim/switch_host.py
	python3 sim/lost_key_files.py
	python3 sim/host_gone.py
