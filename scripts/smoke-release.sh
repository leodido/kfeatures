#!/usr/bin/env bash
# Run on a matching Linux host; requires gh, tar, and GNU timeout.
set -Eeuo pipefail

release=${1:-}
arch=${2:-}
repository=${3:-}
step=validate-input
fail() {
    printf 'Release %q / linux_%q / %s: %s\n' "$release" "$arch" "$step" "$*" >&2
    exit 1
}
trap 'fail "command failed (line $LINENO)"' ERR

# Limit tags to the project's v-prefixed release format, including prereleases.
# Never evaluate input as shell code or allow gh patterns/options/path traversal.
[[ $release =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] || fail 'expected vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]'
[[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'expected OWNER/REPO'
case $arch in
    amd64) machine=x86_64 ;;
    arm64) machine=aarch64 ;;
    *) fail 'expected amd64 or arm64' ;;
esac
version=${release#v}
asset="kfeatures_${version}_linux_${arch}.tar.gz"

step=verify-runner
[[ $(uname -s) == Linux && $(uname -m) == "$machine" ]] || fail "requires native Linux $machine"
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

step=verify-release
published_tag=$(gh release view "$release" --repo "$repository" --json tagName,isDraft --jq 'select(.isDraft == false) | .tagName')
[[ $published_tag == "$release" ]] || fail 'release is missing, draft, or has a different tag'

step="download-$asset"
gh release download "$release" --repo "$repository" --pattern "$asset" --dir "$workdir"
[[ -s "$workdir/$asset" ]] || fail "missing or empty $asset"

step=extract
mkdir "$workdir/extracted"
tar -xzf "$workdir/$asset" -C "$workdir/extracted"
binary="$workdir/extracted/kfeatures"
[[ -f $binary && -x $binary ]] || fail 'archive must contain an executable kfeatures at its root (no chmod repair)'

step='version-startup'
# version performs only the unprivileged baseline probe. Bound hangs as well as crashes.
# Authentication is needed for gh above, not for the downloaded executable.
output=$(env -u GH_TOKEN timeout 30s "$binary" version)
printf '%s\n' "$output"

step='version-metadata'
# First line: kfeatures VERSION [(COMMIT)] [built DATE]. The Kernel line is separate.
IFS=' ' read -r tool actual_version _ <<< "$output"
[[ $tool == kfeatures && $actual_version == "$version" ]] || fail "expected tool version $version; got first line: ${output%%$'\n'*}"
printf 'PASS: %s / linux_%s / %s\n' "$release" "$arch" "$asset"
