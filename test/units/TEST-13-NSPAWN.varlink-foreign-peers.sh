#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Varlink servers inside a container can't translate the PID of a peer from the host's PID namespace
# (SO_PEERCRED reports pid 0), so by default they refuse such connections. With
# $SYSTEMD_VARLINK_ALLOW_FOREIGN_PEERS=1 they accept them, but must treat them as 'nobody'.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

MACHINE="varlink-foreign"

at_exit() {
    set +e

    machinectl terminate "$MACHINE" &>/dev/null
    timeout 30 bash -c "while machinectl status $MACHINE &>/dev/null; do sleep .5; done"
    mountpoint -q /var/lib/machines && timeout 30 bash -c "until umount /var/lib/machines; do sleep .5; done"
    rm -f "/run/systemd/nspawn/$MACHINE.nspawn"
}

trap at_exit EXIT

mkdir -p /var/lib/machines
mount --bind "$(mktemp --tmpdir=/var/tmp -d)" /var/lib/machines

create_dummy_container "/var/lib/machines/$MACHINE"

machine_start() {
    local leader

    machinectl start "$MACHINE"
    leader="$(machinectl show -p Leader --value "$MACHINE")"
    # Wait until the container's service manager answers from within its own PID namespace
    timeout 60 bash -c "until nsenter -t $leader -p -- varlinkctl info /proc/$leader/root/run/systemd/io.systemd.Manager &>/dev/null; do sleep .5; done"
    SOCKET="/proc/$leader/root/run/systemd/io.systemd.Manager"
}

machine_stop() {
    machinectl terminate "$MACHINE"
    timeout 30 bash -c "while machinectl status $MACHINE &>/dev/null; do sleep .5; done"
}

# Default: peers from the host's PID namespace are refused, exactly as before
machine_start
(! varlinkctl info "$SOCKET")
machine_stop

# Opt in via the environment of the container's PID 1
mkdir -p /run/systemd/nspawn
cat >>"/run/systemd/nspawn/$MACHINE.nspawn" <<EOF
[Exec]
Environment=SYSTEMD_VARLINK_ALLOW_FOREIGN_PEERS=1
EOF

machine_start

# Unprivileged reads work, even though we're connecting from the host's PID namespace
varlinkctl info "$SOCKET"
varlinkctl call "$SOCKET" io.systemd.Manager.Describe '{}' | jq -e '.runtime'
varlinkctl call --more "$SOCKET" io.systemd.Unit.List '{}' | grep '"ID":"init.scope"' >/dev/null

# We are root on the host, but the container must not trust that: privileged calls are refused
(! varlinkctl call "$SOCKET" io.systemd.Manager.Reload '{}' 2>/tmp/varlink-foreign.err)
grep "Permission denied" /tmp/varlink-foreign.err
(! varlinkctl call "$SOCKET" io.systemd.Unit.SetProperties \
       '{"name":"init.scope","runtime":true,"properties":{"Markers":["needs-restart"]}}' 2>/tmp/varlink-foreign.err)
grep "Permission denied" /tmp/varlink-foreign.err
rm -f /tmp/varlink-foreign.err

machine_stop
