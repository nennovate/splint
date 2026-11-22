.PHONY: test-network test-resilience

# Two hosts on separate networks through one router, with nothing broken: agents talking across a real
# network path on this machine. Takes under a minute.
test-network:
	python3 sim/resilience/resilience.py --seed 1 --out sim/runs/test-network baseline

# Breaks the network, processes, disk and clocks under real hosts, and counts every message. Takes
# about ten minutes and doesn't belong in check. SEED repeats a run, CASES picks some.
SEED ?= 1
CASES ?=
test-resilience:
	python3 sim/resilience/resilience.py --seed $(SEED) $(CASES)
