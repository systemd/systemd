#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

varlinkctl --help
varlinkctl help --no-pager
varlinkctl --version
varlinkctl --json=help

# TODO: abstract namespace sockets (@...)
# Path to a socket
varlinkctl info /run/systemd/journal/io.systemd.journal
varlinkctl info /run/systemd/../systemd/../../run/systemd/journal/io.systemd.journal
varlinkctl info "./$(realpath --relative-to="$PWD" /run/systemd/journal/io.systemd.journal)"
varlinkctl info unix:/run/systemd/journal/io.systemd.journal
varlinkctl info --json=off /run/systemd/journal/io.systemd.journal
varlinkctl info --json=pretty /run/systemd/journal/io.systemd.journal | jq .
varlinkctl info --json=short /run/systemd/journal/io.systemd.journal | jq .
varlinkctl info -j /run/systemd/journal/io.systemd.journal | jq .

varlinkctl list-interfaces /run/systemd/journal/io.systemd.journal
varlinkctl list-interfaces -j /run/systemd/journal/io.systemd.journal | jq .

varlinkctl list-methods /run/systemd/journal/io.systemd.journal
varlinkctl list-methods -j /run/systemd/journal/io.systemd.journal | jq .

varlinkctl list-methods /run/systemd/journal/io.systemd.journal io.systemd.Journal
varlinkctl list-methods -j /run/systemd/journal/io.systemd.journal io.systemd.Journal | jq .

varlinkctl introspect /run/systemd/journal/io.systemd.journal
varlinkctl introspect -j /run/systemd/journal/io.systemd.journal | jq --seq .

varlinkctl introspect /run/systemd/journal/io.systemd.journal io.systemd.Journal
varlinkctl introspect -j /run/systemd/journal/io.systemd.journal io.systemd.Journal | jq .

varlinkctl list-registry
varlinkctl list-registry -j | jq .
varlinkctl list-registry | grep io.systemd.Manager

if command -v userdbctl >/dev/null; then
    systemctl start systemd-userdbd
    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }'
    varlinkctl call -q /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }'
    varlinkctl call -j /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }' | jq .
    # We ignore the return value of the following two calls, since if no memberships are defined at all this will return a NotFound error, which is OK
    varlinkctl call --more /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' --graceful=io.systemd.UserDatabase.NoRecordFound
    varlinkctl call --quiet --more /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' --graceful=io.systemd.UserDatabase.NoRecordFound
    varlinkctl call --more -j /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' --graceful=io.systemd.UserDatabase.NoRecordFound | jq --seq .
    varlinkctl call --oneway /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }'
    (! varlinkctl call --oneway /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' | grep .)

    if command -v openssl >/dev/null && command -v groupadd >/dev/null; then
        group=haldo
        salt=waldo
        getent group "$group" >/dev/null 2>&1 || groupadd "$group"
        HASH="$(openssl passwd -6 -salt "$salt" baldo)"
        groupmod -p "$HASH" "$group"

        (! run0 -u testuser varlinkctl call --json=pretty \
            /run/systemd/userdb/io.systemd.Multiplexer \
            io.systemd.UserDatabase.GetGroupRecord \
            '{"groupName":"haldo","service":"io.systemd.NameServiceSwitch"}' | grep waldo)
    fi
fi

IDL_FILE="$(mktemp)"
varlinkctl introspect /run/systemd/journal/io.systemd.journal io.systemd.Journal | tee "${IDL_FILE:?}"
varlinkctl validate-idl "$IDL_FILE"
cat /bin/sh >"$IDL_FILE"
(! varlinkctl validate-idl "$IDL_FILE")

if [[ -x /usr/lib/systemd/systemd-pcrextend ]]; then
    # Path to an executable
    varlinkctl info /usr/lib/systemd/systemd-pcrextend
    varlinkctl info exec:/usr/lib/systemd/systemd-pcrextend
    varlinkctl list-interfaces /usr/lib/systemd/systemd-pcrextend
    varlinkctl introspect /usr/lib/systemd/systemd-pcrextend io.systemd.PCRExtend
    varlinkctl introspect /usr/lib/systemd/systemd-pcrextend
fi

# Test various varlink socket units to make sure that we can still connect to the varlink sockets even if the
# services are currently stopped (or restarting).
systemctl stop \
    systemd-networkd.service \
    systemd-hostnamed.service \
    systemd-machined.service \
    systemd-udevd.service
varlinkctl introspect /run/systemd/netif/io.systemd.Network
varlinkctl introspect /run/systemd/io.systemd.Hostname
varlinkctl introspect /run/systemd/machine/io.systemd.Machine
if ! systemd-detect-virt -qc; then
    varlinkctl introspect /run/udev/io.systemd.Udev
fi

# SSH transport
SSHBINDIR="$(mktemp -d)"

rm_rf_sshbindir() {
    rm -rf "$SSHBINDIR"
}

trap rm_rf_sshbindir EXIT

# Create a fake "ssh" binary that validates everything works as expected if invoked for the "ssh-unix:" Varlink transport
cat > "$SSHBINDIR"/ssh <<'EOF'
#!/usr/bin/env bash

set -xe

test "$1" = "-W"
test "$2" = "/run/systemd/journal/io.systemd.journal"
test "$3" = "foobar"

exec socat - UNIX-CONNECT:/run/systemd/journal/io.systemd.journal
EOF
chmod +x "$SSHBINDIR"/ssh

SYSTEMD_SSH="$SSHBINDIR/ssh" varlinkctl info ssh-unix:foobar:/run/systemd/journal/io.systemd.journal

# Now build another fake "ssh" binary that does the same for "ssh-exec:"
cat > "$SSHBINDIR"/ssh <<'EOF'
#!/usr/bin/env bash

set -xe

test "$1" = "-e"
test "$2" = "none"
test "$3" = "-T"
test "$4" = "foobar"
test "$5" = "env"
test "$6" = "SYSTEMD_VARLINK_LISTEN=-"
test "$7" = "systemd-sysext"

SYSTEMD_VARLINK_LISTEN=- exec systemd-sysext
EOF
chmod +x "$SSHBINDIR"/ssh

SYSTEMD_SSH="$SSHBINDIR/ssh" varlinkctl info ssh-exec:foobar:systemd-sysext

# Go through all varlink sockets we can find under /run/systemd/ for some extra coverage
find /run/systemd/ -name "io.systemd*" -type s | while read -r socket; do
    varlinkctl info "$socket"
    varlinkctl info -j "$socket"
    varlinkctl list-interfaces "$socket"
    varlinkctl list-interfaces -j "$socket"
    varlinkctl list-methods "$socket"
    varlinkctl list-methods -j "$socket"
    varlinkctl introspect "$socket"
    varlinkctl introspect -j "$socket"

    varlinkctl list-interfaces "$socket" | while read -r interface; do
        varlinkctl introspect "$socket" "$interface"
    done

done

(! varlinkctl)
(! varlinkctl "")
(! varlinkctl info)
(! varlinkctl info "")
(! varlinkctl info /run/systemd/notify)
(! varlinkctl info /run/systemd/private)
# Relative paths must begin with ./
(! varlinkctl info "$(realpath --relative-to="$PWD" /run/systemd/journal/io.systemd.journal)")
(! varlinkctl info unix:)
(! varlinkctl info unix:"")
(! varlinkctl info exec:)
(! varlinkctl info exec:"")
(! varlinkctl list-interfaces)
(! varlinkctl list-interfaces "")
(! varlinkctl introspect)
(! varlinkctl introspect /run/systemd/journal/io.systemd.journal "")
(! varlinkctl introspect "" "")
(! varlinkctl list-methods /run/systemd/journal/io.systemd.journal "")
(! varlinkctl list-methods -j /run/systemd/journal/io.systemd.journal "")
(! varlinkctl list-methods "")
(! varlinkctl list-methods -j "")
(! varlinkctl call)
(! varlinkctl call "")
(! varlinkctl call "" "")
(! varlinkctl call "" "" "")
(! varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "service" : "io.systemd.ShouldNotExist" }')
(! varlinkctl validate-idl "")
(! varlinkctl validate-idl </dev/null)

varlinkctl info /run/systemd/io.systemd.Hostname
varlinkctl introspect /run/systemd/io.systemd.Hostname io.systemd.Hostname
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

# Validate that --exec results in the very same values
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}' | jq >/tmp/describe1.json
varlinkctl --exec call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}' -- jq >/tmp/describe2.json
cmp /tmp/describe1.json /tmp/describe2.json
rm /tmp/describe1.json /tmp/describe2.json

# test io.systemd.Manager
varlinkctl info /run/systemd/io.systemd.Manager
varlinkctl introspect /run/systemd/io.systemd.Manager io.systemd.Manager
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reload '{}'
# This will disconnect and fail, as the manager reexec and drops connections
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reexecute '{}' ||:

# test io.systemd.Network
varlinkctl info /run/systemd/netif/io.systemd.Network
varlinkctl introspect /run/systemd/netif/io.systemd.Network io.systemd.Network
varlinkctl call /run/systemd/netif/io.systemd.Network io.systemd.Network.Describe '{}'

# test io.systemd.Unit
varlinkctl info /run/systemd/io.systemd.Manager
varlinkctl introspect /run/systemd/io.systemd.Manager io.systemd.Unit
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "multi-user.target"}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": 1}}'
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' |& grep "called without 'more' flag" >/dev/null)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "init.scope", "pid": {"pid": 1}}'
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": ""}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "non-existent.service"}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": -1}}' )
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "multi-user.target", "pid": {"pid": 1}}')
set +o pipefail
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties '{"runtime": true, "name": "non-existent.service", "properties": {"Markers": ["needs-restart"]}}' |& grep "io.systemd.Unit.NoSuchUnit"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties '{"runtime": true, "name": "systemd-journald.service", "properties": {"LoadState": "foobar"}}' |& grep "io.systemd.Unit.PropertyNotSupported"
set -o pipefail

varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"cgroup": "/init.scope"}'
invocation_id="$(systemctl show -P InvocationID systemd-journald.service)"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "{\"invocationID\": \"$invocation_id\"}"
# test for KillContext
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": 0}}' | jq -e '.context.Kill'
# test for AutomountContext/Runtime
automount_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "automount" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$automount_id"
# Use jq to JSON-encode the unit name as it may contain backslash escapes (e.g. \x2d) that
# are not valid JSON escape sequences and would be rejected by varlinkctl's JSON parser.
automount_params=$(jq -cn --arg name "$automount_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$automount_params" | jq -e '.context.Automount'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$automount_params" | jq -e '.runtime.Automount'
# test for MountContext/Runtime
mount_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "mount" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$mount_id"
mount_params=$(jq -cn --arg name "$mount_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$mount_params" | jq -e '.context.Mount'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$mount_params" | jq -e '.runtime.Mount'
# test for PathContext/Runtime
path_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "path" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$path_id"
path_params=$(jq -cn --arg name "$path_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$path_params" | jq -e '.context.Path'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$path_params" | jq -e '.runtime.Path'
# test for ScopeContext/Runtime
scope_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "scope" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$scope_id"
scope_params=$(jq -cn --arg name "$scope_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$scope_params" | jq -e '.context.Scope'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$scope_params" | jq -e '.runtime.Scope'
# test for SocketContext/Runtime
socket_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "socket" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$socket_id"
socket_params=$(jq -cn --arg name "$socket_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$socket_params" | jq -e '.context.Socket'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$socket_params" | jq -e '.runtime.Socket'
# test for SwapContext/Runtime (swap units may not be present on all systems)
swap_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "swap" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
if test -n "$swap_id"; then
    swap_params=$(jq -cn --arg name "$swap_id" '{name: $name}')
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$swap_params" | jq -e '.context.Swap'
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$swap_params" | jq -e '.runtime.Swap'
fi
# test for TimerContext/Runtime
timer_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "timer" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$timer_id"
timer_params=$(jq -cn --arg name "$timer_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$timer_params" | jq -e '.context.Timer'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$timer_params" | jq -e '.runtime.Timer'

# test io.systemd.Metrics
varlinkctl info /run/systemd/report/io.systemd.Manager

varlinkctl list-methods /run/systemd/report/io.systemd.Manager
varlinkctl list-methods -j /run/systemd/report/io.systemd.Manager io.systemd.Metrics | jq .

varlinkctl introspect /run/systemd/report/io.systemd.Manager
varlinkctl introspect -j /run/systemd/report/io.systemd.Manager io.systemd.Metrics | jq .

varlinkctl --more call /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Manager io.systemd.Metrics.Describe {}

# test io.systemd.Manager in user manager
testuser_uid=$(id -u testuser)
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl info "/run/user/$testuser_uid/systemd/io.systemd.Manager"
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl introspect "/run/user/$testuser_uid/systemd/io.systemd.Manager"
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl call "/run/user/$testuser_uid/systemd/io.systemd.Manager" io.systemd.Manager.Describe '{}'

# test io.systemd.Unit in user manager
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl --more call "/run/user/$testuser_uid/systemd/io.systemd.Manager" io.systemd.Unit.List '{}'

# test --upgrade (protocol upgrade)
# The basic --upgrade proxy test is covered by the "varlinkctl serve" tests below (which use
# serve+rev/gunzip as the server). The tests here exercise features that need the Python
# server: file-input (defer fallback), ssh-exec transport (pipe pairs) and --exec mode.
UPGRADE_SOCKET="$(mktemp -d)/upgrade.sock"
UPGRADE_SERVER="$(mktemp)"
cat >"$UPGRADE_SERVER" <<'PYEOF'
#!/usr/bin/env python3
"""Varlink upgrade test server. With a socket path argument, listens on a unix socket.
Without arguments, speaks over stdin/stdout (for ssh-exec: transport testing)."""
import json, os, socket, sys

def sd_notify_ready():
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr[0] == "@":
        addr = "\0" + addr[1:]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(addr)
    s.sendall(b"READY=1")
    s.close()

if len(sys.argv) > 1:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(sys.argv[1])
    sock.listen(1)
    sd_notify_ready()
    conn, _ = sock.accept()
    inp = conn.makefile("rb")
    out = conn.makefile("wb")
else:
    inp = sys.stdin.buffer
    out = sys.stdout.buffer
    conn = sock = None

# Read the varlink request (NUL-terminated JSON)
data = b""
while True:
    chunk = inp.read(1)
    assert chunk, "Connection closed before receiving full varlink request"
    data += chunk
    if b"\0" in data:
        break

msg = json.loads(data.split(b"\0")[0])
received_parameters = msg.get("parameters", {})
out.write(b'{"parameters": {}}\0')
out.flush()

# Upgraded protocol: send a non-JSON banner first to prove we're truly in raw mode,
# then echo the received parameters, then reverse lines from the client
out.write(b"<<< UPGRADED >>>\n")
out.write((json.dumps(received_parameters) + "\n").encode())
out.flush()
for line in inp:
    text = line.decode().rstrip("\n")
    out.write((text[::-1] + "\n").encode())
    out.flush()

if conn:
    conn.close()
if sock:
    sock.close()
PYEOF
chmod +x "$UPGRADE_SERVER"

# Test --upgrade with stdin redirected from a regular file (epoll can't poll regular files,
# so this exercises the sd_event_add_defer fallback path)
UPGRADE_SOCKET2="$(mktemp -d)/upgrade.sock"
systemd-notify --fork -q -- python3 "$UPGRADE_SERVER" "$UPGRADE_SOCKET2"

echo "file input test" > /tmp/test-upgrade-input
result="$(varlinkctl call --upgrade "unix:$UPGRADE_SOCKET2" io.systemd.test.Reverse '{"foo":"file"}' < /tmp/test-upgrade-input)"
echo "$result" | grep "<<< UPGRADED >>>" >/dev/null
echo "$result" | grep '"foo": "file"' >/dev/null
echo "$result" | grep "tset tupni elif" >/dev/null

# Test --upgrade over ssh-exec: transport (pipe pair, not a bidirectional socket).
# This exercises the input_fd != output_fd path in sd_varlink_call_and_upgrade().
# Reuse the same server script without a socket argument - it speaks over stdin/stdout.
cat > "$SSHBINDIR"/ssh <<EOF
#!/usr/bin/env bash
exec python3 "$UPGRADE_SERVER"
EOF
chmod +x "$SSHBINDIR"/ssh

result="$(echo "ssh pipe test" | SYSTEMD_SSH="$SSHBINDIR/ssh" varlinkctl call --upgrade ssh-exec:foobar:test-upgrade io.systemd.test.Reverse '{"foo":"ssh"}')"
echo "$result" | grep "<<< UPGRADED >>>" >/dev/null
echo "$result" | grep '"foo": "ssh"' >/dev/null
echo "$result" | grep "tset epip hss" >/dev/null

# Start another server for --exec test
rm -f "$UPGRADE_SOCKET"
systemd-notify --fork -q -- python3 "$UPGRADE_SERVER" "$UPGRADE_SOCKET"

# Test --exec mode: the upgraded socket becomes stdin/stdout of the child.
# Since stdout goes to the socket (not the terminal), write results to a file for verification.
EXEC_RESULT="$(mktemp)"
varlinkctl call --upgrade --exec "unix:$UPGRADE_SOCKET" io.systemd.test.Reverse '{"foo":"bar"}' -- \
        bash -c "head -2 > '$EXEC_RESULT'; echo 'hello world'; head -1 >> '$EXEC_RESULT'"
grep "<<< UPGRADED >>>" "$EXEC_RESULT" >/dev/null
grep '"foo": "bar"' "$EXEC_RESULT" >/dev/null
grep "dlrow olleh" "$EXEC_RESULT" >/dev/null
rm -f "$EXEC_RESULT"

rm -f "$UPGRADE_SOCKET" "$UPGRADE_SOCKET2" "$UPGRADE_SERVER" /tmp/test-upgrade-input
rm -rf "$(dirname "$UPGRADE_SOCKET")" "$(dirname "$UPGRADE_SOCKET2")"

# Test varlinkctl serve: expose a stdio command via varlink protocol upgrade with socket activation.
# This is the "inetd for varlink" pattern: any stdio tool becomes a varlink service.
SERVE_SOCKET="$(mktemp -d)/serve.sock"

# Test 1: serve rev: proves bidirectional data flow through the upgrade
SERVE_PID=$(systemd-notify --fork -- \
                           systemd-socket-activate -l "$SERVE_SOCKET" -- \
                                   varlinkctl serve io.systemd.test.Reverse rev)

# Verify introspection works on the serve endpoint and shows the upgrade annotation
varlinkctl introspect "unix:$SERVE_SOCKET" io.systemd.test | grep "method Reverse" >/dev/null
varlinkctl introspect "unix:$SERVE_SOCKET" io.systemd.test | grep "Requires 'upgrade' flag" >/dev/null

result="$(echo "hello world" | varlinkctl call --upgrade "unix:$SERVE_SOCKET" io.systemd.test.Reverse '{}')"
echo "$result" | grep "dlrow olleh" >/dev/null
kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
rm -f "$SERVE_SOCKET"

# Test 2: decompress via serve: the "sandboxed decompressor" use-case (the real thing would be a proper
# unit with real sandboxing).
# Pipe gzip-compressed data through a varlinkctl serve + gunzip endpoint and verify round-trip.
SERVE_PID=$(systemd-notify --fork -- \
                           systemd-socket-activate -l "$SERVE_SOCKET" -- \
                                   varlinkctl serve io.systemd.Compress.Decompress gunzip)

SERVE_TMPDIR="$(mktemp -d)"
echo "untrusted data decompressed safely via varlink serve" | gzip > "$SERVE_TMPDIR/compressed.gz"
result="$(varlinkctl call --upgrade "unix:$SERVE_SOCKET" io.systemd.Compress.Decompress '{}' < "$SERVE_TMPDIR/compressed.gz")"
echo "$result" | grep "untrusted data decompressed safely" >/dev/null
kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true

rm -f "$SERVE_SOCKET"
rm -rf "$(dirname "$SERVE_SOCKET")" "$SERVE_TMPDIR"
