#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

unit_success=testsuite-07-pidfile-reload.service
unit_timeout=testsuite-07-pidfile-timeout.service
script_success=/run/testsuite-07-pidfile-reload.sh
script_timeout=/run/testsuite-07-pidfile-timeout.sh
pidfile_success=/run/testsuite-07-pidfile-reload.pid
pidfile_timeout=/run/testsuite-07-pidfile-timeout.pid
gate_success=/run/testsuite-07-pidfile-reload.ready

wait_for_property() {
    local unit="$1" property="$2" expected="$3" value=

    for _ in $(seq 1 200); do
        value="$(systemctl show -P "$property" "$unit")"
        [[ "$value" == "$expected" ]] && return 0
        sleep 0.1
    done

    echo "Timed out waiting for $property=$expected on $unit, last value: ${value:-<unset>}" >&2
    return 1
}

cleanup() {
    set +e

    systemctl stop "$unit_success" "$unit_timeout"
    systemctl reset-failed "$unit_success" "$unit_timeout"
    rm -f \
        /run/systemd/system/"$unit_success" \
        /run/systemd/system/"$unit_timeout" \
        "$script_success" \
        "$script_timeout" \
        "$pidfile_success" \
        "$pidfile_timeout" \
        "$gate_success"
    systemctl daemon-reload
}

trap cleanup EXIT

mkdir -p /run/systemd/system

cat >"$script_success" <<'EOF_SUCCESS'
#!/usr/bin/env bash
set -eu

pidfile=/run/testsuite-07-pidfile-reload.pid
gate=/run/testsuite-07-pidfile-reload.ready

(
    while [[ ! -e "$gate" ]]; do
        sleep 0.1
    done

    echo "$BASHPID" > "$pidfile"
    exec sleep infinity
) &
EOF_SUCCESS
chmod +x "$script_success"

cat >"$script_timeout" <<'EOF_TIMEOUT'
#!/usr/bin/env bash
set -eu

(
    exec sleep infinity
) &
EOF_TIMEOUT
chmod +x "$script_timeout"

cat >/run/systemd/system/"$unit_success" <<'EOF_UNIT_SUCCESS'
[Unit]
Description=TEST-07 PIDFile daemon-reload success

[Service]
Type=forking
ExecStart=/run/testsuite-07-pidfile-reload.sh
PIDFile=/run/testsuite-07-pidfile-reload.pid
TimeoutStartSec=15s
EOF_UNIT_SUCCESS

cat >/run/systemd/system/"$unit_timeout" <<'EOF_UNIT_TIMEOUT'
[Unit]
Description=TEST-07 PIDFile daemon-reload timeout

[Service]
Type=forking
ExecStart=/run/testsuite-07-pidfile-timeout.sh
PIDFile=/run/testsuite-07-pidfile-timeout.pid
TimeoutStartSec=3s
EOF_UNIT_TIMEOUT

systemctl daemon-reload

systemctl start --no-block "$unit_success"
wait_for_property "$unit_success" ActiveState activating
wait_for_property "$unit_success" ControlPID 0
systemctl daemon-reload
touch "$gate_success"
wait_for_property "$unit_success" ActiveState active
assert_eq "$(systemctl show -P MainPID "$unit_success")" "$(cat "$pidfile_success")"

systemctl start --no-block "$unit_timeout"
wait_for_property "$unit_timeout" ActiveState activating
wait_for_property "$unit_timeout" ControlPID 0
systemctl daemon-reload
wait_for_property "$unit_timeout" ActiveState failed
assert_eq "$(systemctl show -P Result "$unit_timeout")" timeout
