#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Basic checks of the systemd-ptybrokerd daemon itself: socket activation, Varlink
# introspection, parameter validation and exit-on-idle behavior.

SOCKET_PATH=/run/systemd/io.systemd.PTYBroker

systemctl start systemd-ptybrokerd.socket
test -S "$SOCKET_PATH"

varlinkctl info "$SOCKET_PATH"
varlinkctl introspect "$SOCKET_PATH" io.systemd.PTYBroker

# Nothing is registered yet, the list should be empty (but succeed)
ptyctl list
ptyctl --quiet list

# Operations on non-existent PTYs must fail cleanly
(! ptyctl monitor no-such-pty-95 </dev/null)
(! ptyctl hangup no-such-pty-95)

# Invalid parameter combinations must be refused
(! varlinkctl call "$SOCKET_PATH" io.systemd.PTYBroker.AcquirePty '{"frontendType":"null","backendType":"take","name":"not a valid name"}')
(! varlinkctl call "$SOCKET_PATH" io.systemd.PTYBroker.AcquirePty '{"frontendType":"null","backendType":"take","user":"root"}')
(! varlinkctl call "$SOCKET_PATH" io.systemd.PTYBroker.AcquirePty '{"frontendType":"null","backendType":"take","lightweight":true}')
(! varlinkctl call "$SOCKET_PATH" io.systemd.PTYBroker.AcquirePty '{"frontendType":"take","backendType":"take","monitor":true}')
(! varlinkctl call "$SOCKET_PATH" io.systemd.PTYBroker.EnrollPty '{"frontendFileDescriptor":0,"frontendType":"take"}')
(! varlinkctl call "$SOCKET_PATH" io.systemd.PTYBroker.ConfigurePty '{"name":"no-such-pty-95","terminalSettings":{"columns":80}}')

# The broker is a socket-activated singleton and is expected to exit on its own
# once it has been idle for a bit, while the socket stays around
timeout 30 bash -c 'while [[ "$(systemctl show -P ActiveState systemd-ptybrokerd.service)" == active ]]; do sleep 1; done'
systemctl is-active systemd-ptybrokerd.socket

# ... and it must come back transparently on the next request
ptyctl list
