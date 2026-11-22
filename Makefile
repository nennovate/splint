# Each group of commands has its own file in make/, so adding one doesn't touch the others.
# `check` is the default because make/core.mk comes first.
include make/core.mk
include $(filter-out make/core.mk,$(wildcard make/*.mk))
