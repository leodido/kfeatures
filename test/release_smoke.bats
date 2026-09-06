#!/usr/bin/env bats
# Exercise real extraction and startup with local archives, without network or Go builds.
setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../scripts/smoke-release.sh"
    export FIXTURE="$BATS_TEST_TMPDIR/fixture"
    export MOCK_TAG=v1.2.3 MOCK_MACHINE=x86_64 MOCK_DOWNLOAD=ok
    mkdir -p "$FIXTURE/bin" "$FIXTURE/archive"
    cat > "$FIXTURE/bin/uname" <<'SH'
#!/usr/bin/env bash
if [[ $1 == -s ]]; then echo Linux; else echo "$MOCK_MACHINE"; fi
SH
    cat > "$FIXTURE/bin/gh" <<'SH'
#!/usr/bin/env bash
[[ $1 == release && $3 == "$MOCK_TAG" && $4 == --repo && $5 == owner/repo ]] || exit 91
case $2 in
    view) printf '%s\n' "${MOCK_PUBLISHED_TAG-$MOCK_TAG}" ;;
    download)
        [[ $6 == --pattern && $7 == "kfeatures_${MOCK_TAG#v}_linux_amd64.tar.gz" && $8 == --dir ]] || exit 92
        [[ $MOCK_DOWNLOAD == ok ]] || exit 93
        cp "$FIXTURE/asset.tar.gz" "$9/$7"
        ;;
esac
SH
    # Avoid a GNU timeout dependency for fixture tests on macOS.
    cat > "$FIXTURE/bin/timeout" <<'SH'
#!/usr/bin/env bash
[[ $1 == 30s ]] || exit 94
shift
exec "$@"
SH
    chmod +x "$FIXTURE/bin/"*
    export PATH="$FIXTURE/bin:$PATH"
    make_archive '1.2.3'
}

make_archive() {
    printf '#!/usr/bin/env bash\nprintf "kfeatures %s (abcdef0) built 2026-05-25T00:00:00Z\\nKernel: 6.8.0\\n"\n' "$1" > "$FIXTURE/archive/kfeatures"
    chmod +x "$FIXTURE/archive/kfeatures"
    tar -czf "$FIXTURE/asset.tar.gz" -C "$FIXTURE/archive" .
}

smoke() {
    run bash "$SCRIPT" "$MOCK_TAG" amd64 owner/repo
}

@test "release smoke: exact version accepts commit/date and separate kernel line" {
    smoke
    [ "$status" -eq 0 ]
    [[ $output == *'PASS: v1.2.3 / linux_amd64'* ]]
}

@test "release smoke: normalizes prerelease and build tag metadata" {
    export MOCK_TAG=v1.2.3-rc.1+build.2
    make_archive '1.2.3-rc.1+build.2'
    smoke
    [ "$status" -eq 0 ]
}

@test "release smoke: rejects arbitrary input before download" {
    for tag in latest ../v1.2.3 'v1.2.3;echo unsafe' 'v1.2.3$(false)'; do
        run bash "$SCRIPT" "$tag" amd64 owner/repo
        [ "$status" -ne 0 ]
        [[ $output == *validate-input* ]]
    done
}

@test "release smoke: rejects mismatched native runner" {
    export MOCK_MACHINE=aarch64
    smoke
    [ "$status" -ne 0 ]
    [[ $output == *verify-runner* ]]
}

@test "release smoke: missing archive identifies download step" {
    export MOCK_DOWNLOAD=missing
    smoke
    [ "$status" -ne 0 ]
    [[ $output == *'v1.2.3 / linux_amd64 / download-kfeatures_1.2.3_linux_amd64.tar.gz'* ]]
}

@test "release smoke: corrupt archive fails extraction" {
    echo broken > "$FIXTURE/asset.tar.gz"
    smoke
    [ "$status" -ne 0 ]
    [[ $output == *'/ extract:'* ]]
}

@test "release smoke: missing binary fails extraction assertion" {
    rm "$FIXTURE/archive/kfeatures"
    tar -czf "$FIXTURE/asset.tar.gz" -C "$FIXTURE/archive" .
    smoke
    [ "$status" -ne 0 ]
    [[ $output == *'executable kfeatures at its root'* ]]
}

@test "release smoke: does not repair missing executable permission" {
    chmod -x "$FIXTURE/archive/kfeatures"
    tar -czf "$FIXTURE/asset.tar.gz" -C "$FIXTURE/archive" .
    smoke
    [ "$status" -ne 0 ]
    [[ $output == *'no chmod repair'* ]]
}

@test "release smoke: startup failure fails even with correct version output" {
    echo 'exit 17' >> "$FIXTURE/archive/kfeatures"
    tar -czf "$FIXTURE/asset.tar.gz" -C "$FIXTURE/archive" .
    smoke
    [ "$status" -ne 0 ]
    [[ $output == *version-startup* ]]
}

@test "release smoke: rejects wrong version and dev fallback" {
    for version in 1.2.30 '(dev)'; do
        make_archive "$version"
        smoke
        [ "$status" -ne 0 ]
        [[ $output == *'version-metadata: expected tool version 1.2.3'* ]]
    done
}

@test "release smoke: rejects draft or mismatched release response" {
    for tag in '' v9.9.9; do
        export MOCK_PUBLISHED_TAG="$tag"
        smoke
        [ "$status" -ne 0 ]
        [[ $output == *'verify-release: release is missing, draft, or has a different tag'* ]]
    done
}
