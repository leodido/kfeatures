#!/usr/bin/env bats
# MCP server-mode tests (stdio JSON-RPC). Cross-platform: we exercise the
# protocol surface (initialize, tools/list, tools/call), tool selection
# (excludes), stream isolation (no host stdio leakage), and session
# survival across business-outcome errors. tools/call results that need a
# live kernel run only on Linux.

load helper

setup_file() {
    build_kfeatures
}

# Send one or more JSON-RPC requests on stdin and return the responses.
# Usage: mcp_call <request> [<request> ...]
#
# Stderr is captured (not discarded) and surfaced when the binary exits
# non-zero. Discarding stderr would mask panics, structcli envelope
# errors emitted before the MCP loop starts (e.g. malformed --mcp args),
# and any future diagnostic the binary writes to stderr in MCP mode.
mcp_call() {
    local input=""
    for req in "$@"; do
        input+="$req"$'\n'
    done
    local stderr_file rc
    stderr_file="$(mktemp)"
    printf "%s" "$input" | "$KFEATURES_BIN" --mcp 2>"$stderr_file"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "kfeatures --mcp exited $rc; stderr: $(cat "$stderr_file")" >&2
    fi
    rm -f "$stderr_file"
}

# Extract one response by id from a multi-line MCP transcript.
# Usage: mcp_response_by_id <id> <transcript>
mcp_response_by_id() {
    local id="$1"
    local transcript="$2"
    printf "%s" "$transcript" | python3 -c "
import sys, json
target = int('$id')
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if d.get('id') == target:
        print(json.dumps(d))
        sys.exit(0)
sys.exit('no response with id ' + str(target))
"
}

@test "mcp: --mcp persistent flag exists on root" {
    run "$KFEATURES_BIN" --help
    assert_success
    assert_output --partial "--mcp"
    assert_output --partial "serve MCP over stdio"
}

@test "mcp: initialize returns protocolVersion and serverInfo" {
    transcript="$(mcp_call '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')"
    response="$(mcp_response_by_id 1 "$transcript")"
    echo "$response" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
r = d['result']
assert r['protocolVersion'] == '2024-11-05', r
assert r['serverInfo']['name'] == 'kfeatures', r
assert 'tools' in r['capabilities'], r
"
}

@test "mcp: tools/list exposes only intended leaf commands" {
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')"
    response="$(mcp_response_by_id 2 "$transcript")"
    # probe / check / config exposed; version + completion-* excluded.
    echo "$response" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
names = sorted(t['name'] for t in d['result']['tools'])
assert names == ['check', 'config', 'probe'], names
"
}

@test "mcp: tool input schema mirrors cobra flags (check has require + json)" {
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')"
    response="$(mcp_response_by_id 2 "$transcript")"
    echo "$response" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
check = next(t for t in d['result']['tools'] if t['name'] == 'check')
schema = check['inputSchema']
props = schema.get('properties', {})
assert 'require' in props, props
assert 'json' in props, props
"
}

@test "mcp: invocation errors flow through the structcli envelope" {
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check","arguments":{"require":"nonexistent"}}}')"
    response="$(mcp_response_by_id 2 "$transcript")"
    echo "$response" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
r = d['result']
assert r['isError'] is True, r
text = r['content'][0]['text']
inner = json.loads(text)
assert inner['error'] == 'invalid_flag_value', inner
assert inner['exit_code'] == 11, inner
"
}

@test "mcp: unknown tool returns JSON-RPC error" {
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"version","arguments":{}}}')"
    response="$(mcp_response_by_id 2 "$transcript")"
    echo "$response" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert 'error' in d, d
assert d['error']['message'] == 'unknown tool', d
"
}

@test "mcp: session survives business-outcome errors and serves subsequent calls" {
    if [[ "$(uname -s)" != "Linux" ]]; then
        skip "requires Linux for live probe"
    fi
    # 3 tools/call requests in one session: a successful check, a failing
    # one (FeatureError, exit 1 in CLI mode), and a probe. The MCP server
    # must reply to all three without exiting after #2.
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check","arguments":{"require":"bpf-syscall","json":true}}}' \
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check","arguments":{"require":"nonexistent"}}}' \
        '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"probe","arguments":{"json":true}}}')"
    # All three tools/call responses must be present and well-formed.
    for id in 2 3 4; do
        response="$(mcp_response_by_id "$id" "$transcript")"
        echo "$response" | python3 -c "import sys, json; json.loads(sys.stdin.read())['result']['content']"
    done
}

@test "mcp: --json outputs are compact (no indent or stray newlines) inside result.content" {
    if [[ "$(uname -s)" != "Linux" ]]; then
        skip "requires Linux for live probe"
    fi
    # Captured stdout is jammed verbatim into result.content[0].text;
    # human-friendly indentation would bloat the wire format with
    # literal "\n" and leading-space sequences. Every JSON payload from
    # a --json invocation must arrive as a single compact line (with at
    # most a single trailing newline from json.Encoder.Encode).
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check","arguments":{"require":"bpf-syscall","json":true}}}' \
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe","arguments":{"json":true}}}')"
    printf "%s\n" "$transcript" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if d.get('id') in (2, 3):
        text = d['result']['content'][0]['text']
        # Strip the single trailing newline json.Encoder.Encode emits.
        body = text.rstrip('\n')
        assert '\n' not in body, f'id {d[\"id\"]}: payload contains newline (indented?): {text!r}'
        assert '  ' not in body, f'id {d[\"id\"]}: payload contains 2-space indent: {text!r}'
        # Sanity: it parses as JSON.
        json.loads(body)
"
}

@test "mcp: stdout is JSON-RPC only, no leakage from command handlers" {
    if [[ "$(uname -s)" != "Linux" ]]; then
        skip "requires Linux for live probe"
    fi
    # Capture stdout in isolation. Every line must be a valid JSON-RPC
    # response; any plain CLI output (sf.String(), printJSON straight to
    # os.Stdout, etc.) would break json.loads on that line.
    transcript="$(mcp_call \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe","arguments":{}}}' \
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check","arguments":{"require":"bpf-syscall"}}}' \
        '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"config","arguments":{"json":true}}}')"
    printf "%s\n" "$transcript" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    assert d.get('jsonrpc') == '2.0', d
    assert 'id' in d, d
"
}
