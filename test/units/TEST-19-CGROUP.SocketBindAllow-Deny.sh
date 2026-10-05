#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test that realizing the cgroup of a unit again replaces its SocketBindAllow=/SocketBindDeny= programs,
# instead of attaching them once more.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
    echo "SocketBindDeny= not supported, skipping."
    exit 77
fi

UNIT=test19socketbind.service

bpf_links() {(
    set +x
    local fd id n=0

    id="$(systemctl show -P ControlGroupId "$UNIT")"
    # PID 1 might close any of its fds meanwhile
    for fd in /proc/1/fdinfo/*; do
        grep -qx "cgroup_id:[[:space:]]*$id" "$fd" 2>/dev/null && n=$((n + 1))
    done
    echo "$n"
)}

at_exit() {
    set +e

    systemctl stop "$UNIT"
    rm -rf "/run/systemd/system/$UNIT" "/run/systemd/system.control/$UNIT.d"
    systemctl daemon-reload
}

trap at_exit EXIT

cat >"/run/systemd/system/$UNIT" <<EOF
[Service]
ExecStart=sleep infinity
SocketBindDeny=any
EOF
systemctl daemon-reload
systemctl start "$UNIT"
n="$(bpf_links)"
if [[ "$n" -eq 0 ]]; then
    echo "SocketBindDeny= not supported, skipping."
    exit 77
fi

# Changing a cgroup attribute realizes the cgroup again
systemctl set-property --runtime "$UNIT" CPUWeight=50
assert_eq "$(bpf_links)" "$n"
