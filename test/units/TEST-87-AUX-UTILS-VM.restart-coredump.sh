#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

UNIT_TEMPLATE="restart-coredump@.service"
HELPER="/run/restart-coredump-crash"
RECEIVER_DROPIN="/run/systemd/system/systemd-coredump@.service.d/50-restart-coredump-gate.conf"
RECEIVER_READY="/run/restart-coredump-receiver-ready"
RECEIVER_RELEASE="/run/restart-coredump-receiver-release"
RESTART_MESSAGE_ID="5eb03494b6584870a536b337290809b3"
suffix="$RANDOM"
default_instance="default-$suffix"
early_instance="early-$suffix"
concurrent_instance="concurrent-$suffix"
default_unit="restart-coredump@$default_instance.service"
early_unit="restart-coredump@$early_instance.service"
concurrent_unit="restart-coredump@$concurrent_instance.service"
default_state="/run/restart-coredump-$default_instance"
early_state="/run/restart-coredump-$early_instance"
concurrent_state="/run/restart-coredump-$concurrent_instance"
manager_log_level=""

cleanup() {
    set +e

    : >"$RECEIVER_RELEASE"
    timeout 60 bash -c 'while systemctl --quiet is-active "systemd-coredump@*.service"; do sleep 0.1; done'
    systemctl stop "$default_unit" "$early_unit" "$concurrent_unit"

    if [[ -n "$manager_log_level" ]]; then
        systemctl log-level "$manager_log_level"
    fi

    rm -rf \
        "/run/systemd/system/$UNIT_TEMPLATE" \
        "/run/systemd/system/$early_unit.d" \
        "/run/systemd/system/$concurrent_unit.d" \
        "${RECEIVER_DROPIN%/*}"
    rm -f \
        "$HELPER" \
        "$RECEIVER_READY" \
        "$RECEIVER_RELEASE" \
        "$default_state".* \
        "$early_state".* \
        "$concurrent_state".*
    systemctl daemon-reload
}

trap cleanup EXIT

(! systemd-detect-virt -cq)
sysctl kernel.core_pattern | grep systemd-coredump >/dev/null
sysctl kernel.core_pattern | grep '%F' >/dev/null

cat >"$HELPER" <<'EOF'
#!/usr/bin/env bash
set -eu

state="/run/restart-coredump-${1:?}"
generation=0
if [[ -r "$state.generation" ]]; then
    read -r generation <"$state.generation"
fi
generation=$((generation + 1))
printf '%s\n' "$generation" >"$state.generation"
printf '%s\n' "$$" >"$state.pid.$generation"

trigger="$state.trigger"
if (( generation > 1 )); then
    if [[ ! -e "$state.arm.$generation" ]]; then
        exec /usr/bin/sleep infinity
    fi

    trigger="$state.trigger.$generation"
fi

# Keep roughly 8 MiB of dirty anonymous memory resident in the process being dumped.
printf -v dirty '%*s' $((8 * 1024 * 1024)) x
: >"$state.ready"
while [[ ! -e "$trigger" ]]; do
    :
done

kill -SEGV "$$"
EOF
chmod +x "$HELPER"

mkdir -p \
    "${RECEIVER_DROPIN%/*}" \
    "/run/systemd/system/$early_unit.d" \
    "/run/systemd/system/$concurrent_unit.d"
cat >"$RECEIVER_DROPIN" <<EOF
[Service]
ExecStartPre=/bin/bash -c 'touch "$RECEIVER_READY"; while [[ ! -e "$RECEIVER_RELEASE" ]]; do sleep 0.05; done'
EOF

cat >"/run/systemd/system/$UNIT_TEMPLATE" <<EOF
[Service]
Type=exec
ExecStart=$HELPER %i
ExecStop=/bin/sh -c 'touch "/run/restart-coredump-%i.exec-stop"'
ExecStopPost=/bin/sh -c 'printf "%%s\n" "\$SERVICE_RESULT:\$EXIT_CODE:\$EXIT_STATUS" > "/run/restart-coredump-%i.stop-post"'
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

cat >"/run/systemd/system/$early_unit.d/override.conf" <<EOF
[Service]
RestartDuringCoredump=yes
EOF
cp "/run/systemd/system/$early_unit.d/override.conf" "/run/systemd/system/$concurrent_unit.d/override.conf"

# Generation 2 of this instance will exercise the single-retired-generation bound.
: >"$concurrent_state.arm.2"

systemctl daemon-reload
systemctl start "$default_unit" "$early_unit" "$concurrent_unit"

timeout 30 bash -c "until [[ -e '$default_state.ready' && -e '$early_state.ready' && -e '$concurrent_state.ready' ]]; do sleep 0.05; done"

default_pid="$(<"$default_state.pid.1")"
early_pid="$(<"$early_state.pid.1")"
concurrent_pid="$(<"$concurrent_state.pid.1")"
default_invocation="$(systemctl show -P InvocationID "$default_unit")"
early_invocation="$(systemctl show -P InvocationID "$early_unit")"
concurrent_invocation="$(systemctl show -P InvocationID "$concurrent_unit")"

[[ "$(systemctl show -P RestartDuringCoredump "$default_unit")" == no ]]
[[ "$(systemctl show -P RestartDuringCoredump "$early_unit")" == yes ]]
[[ "$(systemctl show -P RestartDuringCoredump "$concurrent_unit")" == yes ]]

: >"$default_state.trigger"
: >"$early_state.trigger"
: >"$concurrent_state.trigger"

timeout 30 bash -c "until [[ -e '$RECEIVER_READY' ]]; do sleep 0.05; done"
timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$default_pid/status' >/dev/null; do sleep 0.05; done"
timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$early_pid/status' >/dev/null; do sleep 0.05; done"
timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$concurrent_pid/status' >/dev/null; do sleep 0.05; done"

# The default remains attached to its original main process while the receiver is gated.
[[ "$(systemctl show -P MainPID "$default_unit")" -eq "$default_pid" ]]
[[ "$(systemctl show -P InvocationID "$default_unit")" == "$default_invocation" ]]
[[ "$(systemctl show -P NRestarts "$default_unit")" -eq 0 ]]

# The opted-in unit obtains a new PID and invocation while its original process is still dumping.
timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$early_unit') -eq 1 ]]; do sleep 0.05; done"
new_early_pid="$(systemctl show -P MainPID "$early_unit")"
new_early_invocation="$(systemctl show -P InvocationID "$early_unit")"
[[ "$new_early_pid" -gt 0 ]]
[[ "$new_early_pid" -ne "$early_pid" ]]
[[ "$new_early_invocation" != "$early_invocation" ]]
systemctl --quiet is-active "$early_unit"
grep '^CoreDumping:[[:space:]]*1$' "/proc/$early_pid/status" >/dev/null
[[ "$(<"$early_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$early_state.exec-stop" ]]

journalctl --sync
[[ "$(journalctl -b --no-pager -o json --unit "$early_unit" MESSAGE_ID="$RESTART_MESSAGE_ID" | jq -s length)" -eq 1 ]]

# A separate opted-in unit also restarts once, leaving generation 1 retired while generation 2 runs.
timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$concurrent_unit') -eq 1 ]]; do sleep 0.05; done"
new_concurrent_pid="$(systemctl show -P MainPID "$concurrent_unit")"
new_concurrent_invocation="$(systemctl show -P InvocationID "$concurrent_unit")"
[[ "$new_concurrent_pid" -gt 0 ]]
[[ "$new_concurrent_pid" -ne "$concurrent_pid" ]]
[[ "$new_concurrent_invocation" != "$concurrent_invocation" ]]
systemctl --quiet is-active "$concurrent_unit"
grep '^CoreDumping:[[:space:]]*1$' "/proc/$concurrent_pid/status" >/dev/null
[[ "$(<"$concurrent_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$concurrent_state.exec-stop" ]]

# Generation 2 dumps while generation 1 still occupies the sole retired-coredump record.
manager_log_level="$(systemctl log-level)"
systemctl log-level debug
: >"$concurrent_state.trigger.2"
timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$new_concurrent_pid/status' >/dev/null; do sleep 0.05; done"
timeout 30 bash -c "until journalctl -b --no-pager --unit '$concurrent_unit' --grep='Will wait for coredump process $new_concurrent_pid to exit normally' >/dev/null; do sleep 0.05; done"

# A second early restart is suppressed while the first coredump remains retired.
[[ "$(systemctl show -P MainPID "$concurrent_unit")" -eq "$new_concurrent_pid" ]]
[[ "$(systemctl show -P InvocationID "$concurrent_unit")" == "$new_concurrent_invocation" ]]
[[ "$(systemctl show -P NRestarts "$concurrent_unit")" -eq 1 ]]
[[ ! -e "$concurrent_state.pid.3" ]]
[[ ! -e "$concurrent_state.exec-stop" ]]
journalctl --sync
[[ "$(journalctl -b --no-pager -o json --unit "$concurrent_unit" MESSAGE_ID="$RESTART_MESSAGE_ID" | jq -s length)" -eq 1 ]]

# Reexec PID 1 while the unit has both a retired generation and a suppressed current generation.
systemctl daemon-reexec
busctl --watch-bind=yes call \
    org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 \
    org.freedesktop.DBus.Peer \
    Ping >/dev/null

[[ "$(systemctl show -P MainPID "$early_unit")" -eq "$new_early_pid" ]]
[[ "$(systemctl show -P InvocationID "$early_unit")" == "$new_early_invocation" ]]
[[ "$(systemctl show -P NRestarts "$early_unit")" -eq 1 ]]
grep '^CoreDumping:[[:space:]]*1$' "/proc/$early_pid/status" >/dev/null

[[ "$(systemctl show -P MainPID "$concurrent_unit")" -eq "$new_concurrent_pid" ]]
[[ "$(systemctl show -P InvocationID "$concurrent_unit")" == "$new_concurrent_invocation" ]]
[[ "$(systemctl show -P NRestarts "$concurrent_unit")" -eq 1 ]]
grep '^CoreDumping:[[:space:]]*1$' "/proc/$concurrent_pid/status" >/dev/null
grep '^CoreDumping:[[:space:]]*1$' "/proc/$new_concurrent_pid/status" >/dev/null
journalctl --sync
[[ "$(journalctl -b --no-pager -o json --unit "$concurrent_unit" MESSAGE_ID="$RESTART_MESSAGE_ID" | jq -s length)" -eq 1 ]]
systemctl log-level "$manager_log_level"
manager_log_level=""

: >"$RECEIVER_RELEASE"

timeout 60 bash -c "until [[ ! -e '/proc/$early_pid' && ! -e '/proc/$default_pid' && ! -e '/proc/$concurrent_pid' && ! -e '/proc/$new_concurrent_pid' ]]; do sleep 0.1; done"
timeout 60 bash -c "until coredumpctl info '$early_pid' >/dev/null 2>&1; do sleep 0.1; done"
timeout 60 bash -c "until coredumpctl info '$default_pid' >/dev/null 2>&1; do sleep 0.1; done"
timeout 60 bash -c "until coredumpctl info '$concurrent_pid' >/dev/null 2>&1; do sleep 0.1; done"
timeout 60 bash -c "until coredumpctl info '$new_concurrent_pid' >/dev/null 2>&1; do sleep 0.1; done"
timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$default_unit') -eq 1 ]]; do sleep 0.05; done"
[[ "$(<"$default_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$default_state.exec-stop" ]]

# Reaping the retired process must not disturb the replacement or schedule another restart.
[[ "$(systemctl show -P MainPID "$early_unit")" -eq "$new_early_pid" ]]
[[ "$(systemctl show -P InvocationID "$early_unit")" == "$new_early_invocation" ]]
[[ "$(systemctl show -P NRestarts "$early_unit")" -eq 1 ]]
[[ ! -e "$early_state.exec-stop" ]]
journalctl --sync
[[ "$(journalctl -b --no-pager -o json --unit "$early_unit" MESSAGE_ID="$RESTART_MESSAGE_ID" | jq -s length)" -eq 1 ]]

# The suppressed generation follows the ordinary SIGCHLD path and schedules exactly one later restart.
timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$concurrent_unit') -eq 2 && -e '$concurrent_state.pid.3' ]]; do sleep 0.05; done"
final_concurrent_pid="$(systemctl show -P MainPID "$concurrent_unit")"
final_concurrent_invocation="$(systemctl show -P InvocationID "$concurrent_unit")"
[[ "$final_concurrent_pid" -eq "$(<"$concurrent_state.pid.3")" ]]
[[ "$final_concurrent_pid" -ne "$new_concurrent_pid" ]]
[[ "$final_concurrent_invocation" != "$new_concurrent_invocation" ]]
systemctl --quiet is-active "$concurrent_unit"
[[ "$(<"$concurrent_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$concurrent_state.pid.4" ]]
[[ ! -e "$concurrent_state.exec-stop" ]]
journalctl --sync
[[ "$(journalctl -b --no-pager -o json --unit "$concurrent_unit" MESSAGE_ID="$RESTART_MESSAGE_ID" | jq -s length)" -eq 2 ]]

systemctl stop "$default_unit" "$early_unit" "$concurrent_unit"
