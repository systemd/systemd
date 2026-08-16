#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

UNIT_TEMPLATE="restart-coredump-policy@.service"
HELPER="/run/restart-coredump-policy-crash"
RECEIVER_DROPIN="/run/systemd/system/systemd-coredump@.service.d/50-restart-coredump-policy-gate.conf"
RECEIVER_READY="/run/restart-coredump-policy-receiver-ready"
RECEIVER_RELEASE="/run/restart-coredump-policy-receiver-release"
suffix="$RANDOM"

force_instance="force-$suffix"
prevent_instance="prevent-$suffix"
success_instance="success-$suffix"
direct_instance="direct-$suffix"
sibling_instance="sibling-$suffix"
dynamic_instance="dynamic-$suffix"

force_unit="restart-coredump-policy@$force_instance.service"
prevent_unit="restart-coredump-policy@$prevent_instance.service"
success_unit="restart-coredump-policy@$success_instance.service"
direct_unit="restart-coredump-policy@$direct_instance.service"
sibling_unit="restart-coredump-policy@$sibling_instance.service"
dynamic_unit="restart-coredump-policy@$dynamic_instance.service"
units=("$force_unit" "$prevent_unit" "$success_unit" "$direct_unit" "$sibling_unit" "$dynamic_unit")

force_state="/run/restart-coredump-policy-$force_instance"
prevent_state="/run/restart-coredump-policy-$prevent_instance"
success_state="/run/restart-coredump-policy-$success_instance"
direct_state="/run/restart-coredump-policy-$direct_instance"
sibling_state="/run/restart-coredump-policy-$sibling_instance"
dynamic_runtime="restart-coredump-policy-$dynamic_instance"
dynamic_state="/run/$dynamic_runtime/state"

cleanup() {
    set +e

    : >"$RECEIVER_RELEASE"
    timeout 60 bash -c 'while systemctl --quiet is-active "systemd-coredump@*.service"; do sleep 0.1; done'
    systemctl stop "${units[@]}"

    for unit in "${units[@]}"; do
        rm -rf "/run/systemd/system/$unit.d"
    done
    rm -f "$RECEIVER_DROPIN"
    rmdir "${RECEIVER_DROPIN%/*}"
    rm -rf \
        "/run/systemd/system/$UNIT_TEMPLATE" \
        "/run/$dynamic_runtime"
    rm -f \
        "$HELPER" \
        "$RECEIVER_READY" \
        "$RECEIVER_RELEASE" \
        "$force_state".* \
        "$prevent_state".* \
        "$success_state".* \
        "$direct_state".* \
        "$sibling_state".*
    systemctl daemon-reload
}

wait_for_core() {
    local pid="$1"

    timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$pid/status' >/dev/null; do sleep 0.05; done"
}

wait_for_restart() {
    local unit="$1"
    local count="$2"

    timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$unit') -eq $count ]]; do sleep 0.05; done"
}

wait_for_state() {
    local unit="$1"
    local state="$2"

    timeout 30 bash -c "until [[ \$(systemctl show -P ActiveState '$unit') == '$state' ]]; do sleep 0.05; done"
}

trap cleanup EXIT

(! systemd-detect-virt -cq)
sysctl kernel.core_pattern | grep systemd-coredump >/dev/null
sysctl kernel.core_pattern | grep '%F' >/dev/null

cat >"$HELPER" <<'EOF'
#!/usr/bin/env bash
set -eu

state="${1:?}"
mode="${2:-plain}"
generation=0
if [[ -r "$state.generation" ]]; then
    read -r generation <"$state.generation"
fi
generation=$((generation + 1))
printf '%s\n' "$generation" >"$state.generation"
printf '%s\n' "$$" >"$state.pid.$generation"

if (( generation > 1 )); then
    exec /usr/bin/sleep infinity
fi

if [[ "$mode" == sibling ]]; then
    /usr/bin/sleep infinity &
    printf '%s\n' "$!" >"$state.sibling"
fi

# Make the core larger than the pipe buffers between the kernel and the gated receiver.
printf -v dirty '%*s' $((8 * 1024 * 1024)) x
: >"$state.ready"
while [[ ! -e "$state.trigger" ]]; do
    sleep 0.05
done

kill -SEGV "$$"
EOF
chmod +x "$HELPER"

mkdir -p "${RECEIVER_DROPIN%/*}"
cat >"$RECEIVER_DROPIN" <<EOF
[Service]
ExecStartPre=/bin/bash -c 'touch "$RECEIVER_READY"; while [[ ! -e "$RECEIVER_RELEASE" ]]; do sleep 0.05; done'
EOF

cat >"/run/systemd/system/$UNIT_TEMPLATE" <<EOF
[Service]
Type=exec
ExecStart=$HELPER /run/restart-coredump-policy-%i plain
ExecStop=/bin/sh -c 'touch "/run/restart-coredump-policy-%i.exec-stop"'
ExecStopPost=/bin/sh -c 'printf "%%s\n" "\$SERVICE_RESULT:\$EXIT_CODE:\$EXIT_STATUS" > "/run/restart-coredump-policy-%i.stop-post"'
RestartDuringCoredump=yes
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

for unit in "${units[@]}"; do
    mkdir -p "/run/systemd/system/$unit.d"
done

cat >"/run/systemd/system/$force_unit.d/override.conf" <<EOF
[Service]
Restart=no
RestartForceExitStatus=SIGSEGV
EOF

cat >"/run/systemd/system/$prevent_unit.d/override.conf" <<EOF
[Service]
Restart=always
RestartPreventExitStatus=SIGSEGV
EOF

cat >"/run/systemd/system/$success_unit.d/override.conf" <<EOF
[Service]
Restart=on-failure
SuccessExitStatus=SIGSEGV
EOF

cat >"/run/systemd/system/$direct_unit.d/override.conf" <<EOF
[Service]
Restart=on-failure
RestartMode=direct
RestartSec=3s
EOF

cat >"/run/systemd/system/$sibling_unit.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=$HELPER $sibling_state sibling
EOF

cat >"/run/systemd/system/$dynamic_unit.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=$HELPER $dynamic_state plain
ExecStop=
ExecStop=/bin/sh -c 'touch "$dynamic_state.exec-stop"'
ExecStopPost=
ExecStopPost=/bin/sh -c 'printf "%%s\n" "\$SERVICE_RESULT:\$EXIT_CODE:\$EXIT_STATUS" > "$dynamic_state.stop-post"'
DynamicUser=yes
RuntimeDirectory=$dynamic_runtime
RuntimeDirectoryPreserve=restart
EOF

systemctl daemon-reload
systemctl start "${units[@]}"

timeout 30 bash -c "until [[ -e '$force_state.ready' && -e '$prevent_state.ready' && -e '$success_state.ready' && -e '$direct_state.ready' && -e '$sibling_state.ready' && -e '$dynamic_state.ready' ]]; do sleep 0.05; done"

force_pid="$(<"$force_state.pid.1")"
prevent_pid="$(<"$prevent_state.pid.1")"
success_pid="$(<"$success_state.pid.1")"
direct_pid="$(<"$direct_state.pid.1")"
sibling_pid="$(<"$sibling_state.pid.1")"
sibling_worker="$(<"$sibling_state.sibling")"
dynamic_pid="$(<"$dynamic_state.pid.1")"

force_invocation="$(systemctl show -P InvocationID "$force_unit")"
prevent_invocation="$(systemctl show -P InvocationID "$prevent_unit")"
success_invocation="$(systemctl show -P InvocationID "$success_unit")"
direct_invocation="$(systemctl show -P InvocationID "$direct_unit")"
sibling_invocation="$(systemctl show -P InvocationID "$sibling_unit")"
dynamic_invocation="$(systemctl show -P InvocationID "$dynamic_unit")"

: >"$force_state.trigger"
: >"$prevent_state.trigger"
: >"$success_state.trigger"
: >"$sibling_state.trigger"
: >"$dynamic_state.trigger"

timeout 30 bash -c "until [[ -e '$RECEIVER_READY' ]]; do sleep 0.05; done"
wait_for_core "$force_pid"
wait_for_core "$prevent_pid"
wait_for_core "$success_pid"
wait_for_core "$sibling_pid"
wait_for_core "$dynamic_pid"

# RestartForceExitStatus= overrides Restart=no, including on the early path.
wait_for_restart "$force_unit" 1
new_force_pid="$(systemctl show -P MainPID "$force_unit")"
[[ "$new_force_pid" -gt 0 ]]
[[ "$new_force_pid" -ne "$force_pid" ]]
[[ "$(systemctl show -P InvocationID "$force_unit")" != "$force_invocation" ]]
systemctl --quiet is-active "$force_unit"
grep '^CoreDumping:[[:space:]]*1$' "/proc/$force_pid/status" >/dev/null
[[ "$(<"$force_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$force_state.exec-stop" ]]

# The direct restart uses the ordinary RestartSec= timer and stop-post machinery.
: >"$direct_state.trigger"
wait_for_core "$direct_pid"
[[ "$(systemctl show -P NRestarts "$direct_unit")" -eq 0 ]]
sleep 1
[[ "$(systemctl show -P NRestarts "$direct_unit")" -eq 0 ]]
wait_for_restart "$direct_unit" 1
new_direct_pid="$(systemctl show -P MainPID "$direct_unit")"
[[ "$new_direct_pid" -gt 0 ]]
[[ "$new_direct_pid" -ne "$direct_pid" ]]
[[ "$(systemctl show -P InvocationID "$direct_unit")" != "$direct_invocation" ]]
systemctl --quiet is-active "$direct_unit"
grep '^CoreDumping:[[:space:]]*1$' "/proc/$direct_pid/status" >/dev/null
[[ "$(<"$direct_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$direct_state.exec-stop" ]]

# These policy decisions and conservative eligibility checks all retain the old main PID.
for unit in "$prevent_unit" "$success_unit" "$sibling_unit" "$dynamic_unit"; do
    [[ "$(systemctl show -P NRestarts "$unit")" -eq 0 ]]
done
[[ "$(systemctl show -P MainPID "$prevent_unit")" -eq "$prevent_pid" ]]
[[ "$(systemctl show -P InvocationID "$prevent_unit")" == "$prevent_invocation" ]]
[[ "$(systemctl show -P MainPID "$success_unit")" -eq "$success_pid" ]]
[[ "$(systemctl show -P InvocationID "$success_unit")" == "$success_invocation" ]]
[[ "$(systemctl show -P MainPID "$sibling_unit")" -eq "$sibling_pid" ]]
[[ "$(systemctl show -P InvocationID "$sibling_unit")" == "$sibling_invocation" ]]
[[ "$(systemctl show -P MainPID "$dynamic_unit")" -eq "$dynamic_pid" ]]
[[ "$(systemctl show -P InvocationID "$dynamic_unit")" == "$dynamic_invocation" ]]
kill -0 "$sibling_worker"

: >"$RECEIVER_RELEASE"
timeout 60 bash -c 'while systemctl --quiet is-active "systemd-coredump@*.service"; do sleep 0.1; done'
timeout 60 bash -c "until [[ ! -e '/proc/$force_pid' && ! -e '/proc/$prevent_pid' && ! -e '/proc/$success_pid' && ! -e '/proc/$direct_pid' && ! -e '/proc/$sibling_pid' && ! -e '/proc/$dynamic_pid' ]]; do sleep 0.1; done"

# RestartPreventExitStatus= wins over Restart=always.
wait_for_state "$prevent_unit" failed
[[ "$(systemctl show -P NRestarts "$prevent_unit")" -eq 0 ]]
[[ "$(<"$prevent_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$prevent_state.exec-stop" ]]

# A successful fatal signal suppresses the early path. Core-dumping signals remain failures in the
# ordinary SIGCHLD path, so Restart=on-failure only restarts this service after the dump is released.
wait_for_restart "$success_unit" 1
[[ "$(systemctl show -P MainPID "$success_unit")" -ne "$success_pid" ]]
[[ "$(systemctl show -P InvocationID "$success_unit")" != "$success_invocation" ]]
systemctl --quiet is-active "$success_unit"
[[ "$(<"$success_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$success_state.exec-stop" ]]

# An extra TGID and invocation-scoped runtime ownership also force the normal delayed restart path.
wait_for_restart "$sibling_unit" 1
wait_for_restart "$dynamic_unit" 1
[[ "$(systemctl show -P MainPID "$sibling_unit")" -ne "$sibling_pid" ]]
[[ "$(systemctl show -P InvocationID "$sibling_unit")" != "$sibling_invocation" ]]
[[ "$(systemctl show -P MainPID "$dynamic_unit")" -ne "$dynamic_pid" ]]
[[ "$(systemctl show -P InvocationID "$dynamic_unit")" != "$dynamic_invocation" ]]
systemctl --quiet is-active "$sibling_unit"
systemctl --quiet is-active "$dynamic_unit"
[[ ! -e "/proc/$sibling_worker" ]]
[[ "$(<"$sibling_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ "$(<"$dynamic_state.stop-post")" == "core-dump:dumped:SEGV" ]]
[[ ! -e "$sibling_state.exec-stop" ]]
[[ ! -e "$dynamic_state.exec-stop" ]]

# Reaping retired processes cannot disturb either early replacement.
[[ "$(systemctl show -P MainPID "$force_unit")" -eq "$new_force_pid" ]]
[[ "$(systemctl show -P NRestarts "$force_unit")" -eq 1 ]]
[[ "$(systemctl show -P MainPID "$direct_unit")" -eq "$new_direct_pid" ]]
[[ "$(systemctl show -P NRestarts "$direct_unit")" -eq 1 ]]

systemctl stop "${units[@]}"
