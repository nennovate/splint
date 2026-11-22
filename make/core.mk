.PHONY: check rules rust deps e2e vectors

check: rules rust deps verifier e2e test-adapter test-install test-owner-page

rules:
	python3 tools/checks/test_check_repo_rules.py
	python3 tools/checks/check_repo_rules.py
	python3 tools/checks/check_ci_shards.py
	python3 tools/checks/test_ci_shards.py
	python3 tools/vectors/test_spec.py

rust:
	cd packages && cargo fmt --all --check
	cd packages && cargo clippy --workspace --all-targets --all-features --quiet -- -D warnings
	cd packages && cargo test --workspace --quiet

# Advisories at warn level, so a yank shows. The rest at error, as duplicate versions are many.
deps:
	cd packages && cargo deny --log-level warn check advisories
	cd packages && cargo deny --log-level error check bans licenses sources

# Runs the real hosts and Signets against Postgres in Docker.
e2e:
	cd packages && cargo test --release --quiet -p splint-core --lib transport
	python3 sim/tls_rules.py
	python3 sim/e2e.py
	python3 sim/peers_file.py
	python3 sim/open_federation.py
	python3 sim/host_id.py
	python3 sim/host_closing.py
	python3 sim/managed_requests.py
	python3 sim/owner_control.py
	python3 sim/owner_keys.py
	python3 sim/identity_recovery.py
	python3 sim/change_notices.py
	python3 sim/hostile_home_host.py
	python3 sim/host_limits.py
	python3 sim/hanging_up.py
	python3 sim/host_operator.py
	python3 sim/key_safety.py
	python3 sim/colluders.py
	python3 sim/contact_rules.py
	python3 sim/invites.py
	python3 sim/reach_and_permissions.py
	python3 sim/outbound_text.py
	python3 sim/readable_records.py
	python3 sim/payments.py
	python3 sim/grants.py
	python3 sim/fooled_agent.py
	python3 sim/sealed.py
	python3 sim/unopened_mail.py
	python3 sim/sent_mail.py
	python3 sim/waiting.py
	python3 sim/listening.py
	python3 sim/kept_listener.py
	python3 sim/retire_agent.py
	python3 sim/shell_agent.py
	python3 sim/delegation.py
	python3 sim/agent_asks.py
	python3 sim/asked_by_link.py
	python3 sim/cleanup_check.py

# Rewrites spec/vectors/. Only needed when a format changes, and make check doesn't run it.
vectors:
	uv run --quiet --no-project --python 3.13 --with cryptography==50.0.0 python tools/vectors/generate.py
