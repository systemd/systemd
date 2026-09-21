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
DROPIN_DIR="/run/systemd/system/systemd-nspawn@$MACHINE.service.d"
ERR="$(mktemp)"

at_exit() {
    set +e

    machinectl terminate "$MACHINE" &>/dev/null
    timeout 30 bash -c "while machinectl status $MACHINE &>/dev/null; do sleep .5; done"
    rm -rf "$DROPIN_DIR" "/var/lib/machines/$MACHINE" "$ERR"
    systemctl daemon-reload
}

trap at_exit EXIT

[[ "$(systemd-detect-virt)" == "qemu" ]] && TIMEOUT=120 || TIMEOUT=60

machine_start() {
    local leader

    # Boot a transient copy of the host's rootfs, so that the container runs a real service manager
    # built from this tree. Extra arguments are passed to systemd-nspawn.
    mkdir -p "/var/lib/machines/$MACHINE" "$DROPIN_DIR"
    cat >"$DROPIN_DIR/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=systemd-nspawn --quiet --link-journal=try-guest --keep-unit --machine=%i --boot \
                         --volatile=yes --directory=/ --bind-ro=/etc --inaccessible=/etc/machine-id $*
EOF
    systemctl daemon-reload

    machinectl start "$MACHINE"
    timeout "$TIMEOUT" bash -xec "until systemd-run -M '$MACHINE' -q --wait --pipe true; do sleep .5; done"

    leader="$(machinectl show -p Leader --value "$MACHINE")"
    SOCKET="/proc/$leader/root/run/systemd/io.systemd.Manager"
    test -S "$SOCKET"
}

machine_stop() {
    machinectl terminate "$MACHINE"
    timeout 30 bash -c "while machinectl status $MACHINE &>/dev/null; do sleep .5; done"
}

# Default: peers from the host's PID namespace are refused, exactly as before. The server accepts the
# connection and immediately closes it again, which is what distinguishes the refusal from other errors.
machine_start
(! varlinkctl info "$SOCKET" 2>"$ERR")
grep -E "Connection reset by peer|Broken pipe" "$ERR"
machine_stop

# Opt in via the environment of the container's PID 1
machine_start --setenv=SYSTEMD_VARLINK_ALLOW_FOREIGN_PEERS=1

# Unprivileged reads work, even though we're connecting from the host's PID namespace
varlinkctl info "$SOCKET"
varlinkctl call "$SOCKET" io.systemd.Manager.Describe '{}' | jq -e '.runtime'
varlinkctl call --more "$SOCKET" io.systemd.Unit.List '{}' | grep '"ID":"init.scope"' >/dev/null

# We are root on the host, but the container must not trust that: privileged calls are refused
(! varlinkctl call "$SOCKET" io.systemd.Manager.Reload '{}' 2>"$ERR")
grep "Permission denied" "$ERR"
(! varlinkctl call "$SOCKET" io.systemd.Unit.SetProperties \
       '{"name":"init.scope","runtime":true,"properties":{"Markers":["needs-restart"]}}' 2>"$ERR")
grep "Permission denied" "$ERR"

# Lookups by the peer's own PID must not resolve to anything either
(! varlinkctl call "$SOCKET" io.systemd.Unit.List '{"pid":{"pid":0}}' 2>"$ERR")
grep "Permission denied" "$ERR"

machine_stop
