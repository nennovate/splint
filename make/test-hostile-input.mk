.PHONY: test-hostile-input

# Hostile input at every parser, for about 25 minutes. Set SPLINT_FUZZ_SEED and SPLINT_FUZZ_SECS for the
# parsers, and SPLINT_FUZZ_MINUTES for the running host and Signet. Needs Docker. Each run prints its seed.
test-hostile-input:
	cd packages && cargo test --release -p splint-core --test hostile_input -- --ignored --nocapture
	python3 sim/hostile_input.py
