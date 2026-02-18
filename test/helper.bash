#!/usr/bin/env bash

export BATS_LIB_PATH="${BATS_LIB_PATH:-/usr/lib}"

bats_load_library bats-support
bats_load_library bats-assert

# Build the CLI binary once per test file.
# Called from setup_file in each .bats file.
build_kfeatures() {
    KFEATURES_BIN="${BATS_FILE_TMPDIR}/kfeatures"
    export KFEATURES_BIN
    go build -o "$KFEATURES_BIN" ./cmd/kfeatures
}
