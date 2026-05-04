SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

GO ?= go
AWK ?= awk
PKG ?= ./...
CMD_PKG ?= ./cmd/kfeatures
BIN_DIR ?= bin
BIN_NAME ?= kfeatures
BIN ?= $(BIN_DIR)/$(BIN_NAME)
TEST_FLAGS ?=

.DEFAULT_GOAL := help

COVER_PROFILE ?= coverage.out
COVER_THRESHOLD ?= 90
# Files gated by `cover-check`. Globs match the basename of each entry
# in the coverage profile; extend this list when a new feature ships
# with its own files (see CONTRIBUTING.md → Coverage gate).
#
# Scoping note: the gate covers public/library files only. Internal
# tools (kvgen, covercheck) have informational coverage via `make
# cover` but are not gated, because their happy paths are exercised by
# the scheduled refresh workflow against live network data.
COVER_FILES ?= \
	probe_elf.go \
	probe_elf_extract.go \
	probe_elf_core.go \
	probe_elf_warnings.go \
	requirement_min_kernel.go \
	internal/kernelversions/kernelversions.go

.PHONY: help deps verify-deps vet generate build test clean all cover cover-check

help: ## Show available targets.
	@if command -v $(AWK) >/dev/null 2>&1; then \
		$(AWK) 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {name = $$1; desc = $$2; if (length(name) > width) width = length(name); names[++n] = name; descs[name] = desc} END {for (i = 1; i <= n; i++) {name = names[i]; printf "%-*s %s\n", width + 2, name, descs[name]}}' $(MAKEFILE_LIST); \
	else \
		lines="$$(grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/')"; \
		width=0; \
		while IFS=$$'\t' read -r name desc; do \
			[ -n "$$name" ] || continue; \
			if [ $${#name} -gt $$width ]; then width=$${#name}; fi; \
		done <<< "$$lines"; \
		while IFS=$$'\t' read -r name desc; do \
			[ -n "$$name" ] || continue; \
			printf "%-*s %s\n" $$((width + 2)) "$$name" "$$desc"; \
		done <<< "$$lines"; \
	fi

deps: ## Download Go module dependencies.
	$(GO) mod download

verify-deps: ## Verify module dependencies.
	$(GO) mod verify

vet: ## Run go vet checks.
	$(GO) vet $(PKG)

generate: ## Run go:generate directives.
	$(GO) generate $(PKG)

build: generate ## Build the CLI binary.
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN) $(CMD_PKG)

test: ## Run the test suite.
	$(GO) test $(TEST_FLAGS) $(PKG)

cover: ## Produce a coverage profile at $(COVER_PROFILE).
	$(GO) test -covermode=atomic -coverprofile=$(COVER_PROFILE) $(PKG)

cover-check: cover ## Enforce per-file coverage threshold on gated files.
	@$(GO) run ./internal/tools/covercheck \
		--profile=$(COVER_PROFILE) \
		--threshold=$(COVER_THRESHOLD) \
		$(foreach f,$(COVER_FILES),--file=$(f))

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR)

all: test build ## Run tests and build.
