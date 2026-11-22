.PHONY: verifier fuzz-verifier

# The independent verifier, written in Go from docs/protocol.md alone, against every shared vector it
# has a check for. Its test names the kinds of check it has none for yet.
verifier:
	@cd packages/verifier && unformatted=$$(gofmt -l .) && if [ -n "$$unformatted" ]; then echo "needs gofmt: $$unformatted"; exit 1; fi
	cd packages/verifier && go vet ./... && go test -count=1 ./...

# Fuzzes each parser for a while. make check runs only their seeds.
FUZZ_TIME ?= 30s
fuzz-verifier:
	cd packages/verifier && for target in $$(go test -list '^Fuzz' . | grep '^Fuzz'); do \
		go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZ_TIME) . || exit 1; done
