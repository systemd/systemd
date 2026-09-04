#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Basic checks of the systemd-ptybrokerd daemon itself: socket activation, Varlink
# introspection, parameter validation and exit-on-idle behavior.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

SOCKET_PATH=/run/systemd/io.systemd.PTYBroker

systemctl start systemd-ptybrokerd.socket
test -S "$SOCKET_PATH"

varlinkctl info "$SOCKET_PATH"
varlinkctl introspect "$SOCKET_PATH" io.systemd.PTYBroker

# Nothing is registered yet, the list should be empty (but succeed)
ptyctl list
ptyctl --quiet list

# Runs a command that is expected to fail, and checks that its output mentions the
# expected error. (Merely checking for failure would also be satisfied by an
# unrelated problem, such as a broken connection to the broker.)
expect_failure_with() {
    local expected="$1"
    shift

    local out
    if out="$("$@" 2>&1)"; then
        echo "'$*' unexpectedly succeeded" >&2
        return 1
    fi

    grep -F "$expected" <<<"$out" >/dev/null
}

# Calls the specified method, expecting it to fail with the specified Varlink error.
expect_error() {
    local method="$1" payload="$2" error="$3"

    # --graceful turns the expected error into success, and dumps its parameters
    varlinkctl call --graceful="$error" "$SOCKET_PATH" "io.systemd.PTYBroker.$method" "$payload" >/dev/null
}

# Same, but for InvalidParameter, additionally checking the offending parameter is named
expect_invalid_parameter() {
    local method="$1" payload="$2" field="$3"

    varlinkctl call --graceful=org.varlink.service.InvalidParameter "$SOCKET_PATH" "io.systemd.PTYBroker.$method" "$payload" \
        | jq -e --arg f "$field" '.parameter == $f' >/dev/null
}

# Operations on non-existent PTYs must fail cleanly
expect_failure_with io.systemd.PTYBroker.NoSuchPty ptyctl monitor no-such-pty-95 </dev/null
expect_failure_with io.systemd.PTYBroker.NoSuchPty ptyctl hangup no-such-pty-95
expect_error ConfigurePty '{"name":"no-such-pty-95","terminalSettings":{"columns":80}}' io.systemd.PTYBroker.NoSuchPty

# Invalid parameter combinations must be refused
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"take","name":"not a valid name"}' name
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"take","user":"root"}' user
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"take","lightweight":true}' lightweight
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"take","commandLine":["/bin/true"]}' commandLine
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"take","viaShell":true}' viaShell
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"shell","viaShell":false}' viaShell
expect_invalid_parameter AcquirePty '{"frontendType":"take","backendType":"take","monitor":true}' monitor
expect_invalid_parameter AcquirePty '{"frontendType":"null","backendType":"take","osc2811":true}' osc2811
expect_invalid_parameter EnrollPty '{"frontendFileDescriptor":0,"frontendType":"take"}' frontendType

# Monitoring requires a connection upgrade, which a plain method call does not offer
expect_error AcquirePty '{"frontendType":"null","backendType":"take","monitor":true}' org.varlink.service.ExpectedUpgrade

# A successful EnrollPty call: enroll a locally allocated PTY master with the broker in 'log' mode. This
# needs neither a container nor a unit, hence covers the fd import, name registration and deregistration
# paths of the method unconditionally. Bounded, so that a broker that never replies fails right here rather
# than hanging until the global test timeout.
timeout 30 python3 <<'EOF'
import json
import os
import pty
import subprocess

master, slave = pty.openpty()

out = subprocess.run(
    ['varlinkctl', 'call', f'--push-fd={master}', '/run/systemd/io.systemd.PTYBroker',
     'io.systemd.PTYBroker.EnrollPty',
     json.dumps({
         'frontendFileDescriptor': 0,
         'frontendType': 'log',
         'name': 'pty95-enroll',
         'tag': 'pty95-enroll-tag',
         'backendPath': os.ttyname(slave),
     })],
    pass_fds=[master], check=True, stdout=subprocess.PIPE, text=True).stdout
reply = json.loads(out)
assert reply['name'] == 'pty95-enroll', reply
assert reply['frontendType'] == 'log', reply
assert reply['backendType'] == 'take', reply

# The enrolled pty must show up in the broker's listing
listing = subprocess.run(['ptyctl', 'list'], check=True, stdout=subprocess.PIPE, text=True).stdout
assert 'pty95-enroll' in listing, listing

# Output written to the backend must end up in the journal under the tag (verified in shell below), and
# closing both ends must deregister the pty again
os.write(slave, b'hello-pty95-enroll-marker\r\n')
os.close(slave)
os.close(master)
EOF

timeout 30 bash -c 'until journalctl -q -t pty95-enroll-tag | grep hello-pty95-enroll-marker >/dev/null; do journalctl --sync; sleep 1; done'
wait_for_pty_deregistration pty95-enroll

# The broker is a socket-activated singleton: it is running right now (we just
# talked to it), but is expected to exit on its own once it has been idle for a
# bit, while the socket stays around
systemctl is-active systemd-ptybrokerd.service
timeout 30 bash -c 'while systemctl is-active systemd-ptybrokerd.service >/dev/null; do sleep 1; done'
systemctl is-active systemd-ptybrokerd.socket

# ... and it must come back transparently on the next request
ptyctl list
