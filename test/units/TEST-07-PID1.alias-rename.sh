#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

run_test() {
    local reload_cmd="${1:?}"
    local orig_pid new_pid

    echo ""
    echo "========================================="
    echo "Testing rename preservation with: systemctl $reload_cmd"
    echo "========================================="

    cat >/run/systemd/system/rename.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF

    systemctl daemon-reload
    systemctl start rename.service

    orig_pid=$(systemctl show -P MainPID rename.service)
    (( orig_pid != 0 ))

    # The old name becomes an alias to the new canonical unit...
    rm -f /run/systemd/system/rename.service
    cat >/run/systemd/system/the-unit-formerly-known-as-rename.service <<'EOF'
[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
    ln -sf /run/systemd/system/the-unit-formerly-known-as-rename.service /run/systemd/system/rename.service

    systemctl "$reload_cmd"

    # ...and the running service must stay tracked across the rename.
    new_pid=$(systemctl show -P MainPID the-unit-formerly-known-as-rename.service)
    (( new_pid == orig_pid ))
    (( $(systemctl show -P MainPID rename.service) == orig_pid ))
    [[ "$(systemctl show -P ActiveState the-unit-formerly-known-as-rename.service)" == active ]]
    [[ "$(systemctl show -P ActiveState rename.service)" == active ]]
}

cleanup_test_units() {
    systemctl stop the-unit-formerly-known-as-rename.service 2>/dev/null || true
    systemctl stop rename.service 2>/dev/null || true
    rm -f /run/systemd/system/rename.service
    rm -f /run/systemd/system/the-unit-formerly-known-as-rename.service
    systemctl daemon-reload
}

trap cleanup_test_units EXIT

run_test daemon-reload
cleanup_test_units
run_test daemon-reexec
