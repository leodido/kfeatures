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

.PHONY: help deps verify-deps vet generate build test clean all

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

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR)

all: test build ## Run tests and build.
