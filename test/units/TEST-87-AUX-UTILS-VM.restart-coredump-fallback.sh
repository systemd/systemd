#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

suffix="$RANDOM"
base="/run/restart-coredump-fallback-$suffix"
helper="$base/helper"
dbus_helper="$base/dbus-helper.py"
dbus_interpreter="$base/restart-coredump-dbus-helper"
receiver_dropin="/run/systemd/system/systemd-coredump@.service.d/50-restart-coredump-fallback-gate.conf"
receiver_ready="$base/receiver-ready"
receiver_release="$base/receiver-release"

worker_unit="restart-coredump-fallback-worker-$suffix.service"
dbus_unit="restart-coredump-fallback-dbus-$suffix.service"
manual_unit="restart-coredump-fallback-manual-$suffix.service"
limit_unit="restart-coredump-fallback-limit-$suffix.service"
forge_unit="restart-coredump-fallback-forge-$suffix.service"
units=("$worker_unit" "$dbus_unit" "$manual_unit" "$limit_unit" "$forge_unit")

worker_state="$base/worker"
dbus_state="$base/dbus"
manual_state="$base/manual"
limit_state="$base/limit"
forge_state="$base/forge"
manual_stop_release="$manual_state.stop-release"
# This name is allowed by the integration-test D-Bus policy shipped in mkosi.extra.
bus_name="systemd.test.ExecStopPost"

cleanup() {
    set +e

    : >"$receiver_release"
    : >"$manual_stop_release"
    timeout 60 bash -c 'while systemctl --quiet is-active "systemd-coredump@*.service"; do sleep 0.1; done'
    systemctl stop "${units[@]}"
    systemctl reset-failed "${units[@]}"

    for unit in "${units[@]}"; do
        rm -f "/run/systemd/system/$unit"
    done
    rm -f "$receiver_dropin"
    rmdir "${receiver_dropin%/*}"
    rm -rf "$base"
    systemctl daemon-reload
}

wait_for_core() {
    local pid="$1"

    timeout 30 bash -c "until grep '^CoreDumping:[[:space:]]*1$' '/proc/$pid/status' >/dev/null; do sleep 0.05; done"
}

wait_for_restart() {
    local unit="$1"

    timeout 30 bash -c "until [[ \$(systemctl show -P NRestarts '$unit') -eq 1 ]]; do sleep 0.05; done"
}

mkdir -p "$base" "${receiver_dropin%/*}"
trap cleanup EXIT

(! systemd-detect-virt -cq)
sysctl kernel.core_pattern | grep systemd-coredump >/dev/null
sysctl kernel.core_pattern | grep '%F' >/dev/null

cat >"$helper" <<'EOF'
#!/usr/bin/env bash
set -eu

state="${1:?}"
mode="${2:?}"
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

if [[ "$mode" == worker ]]; then
    (
        printf -v dirty '%*s' $((8 * 1024 * 1024)) x
        printf '%s\n' "$BASHPID" >"$state.worker"
        : >"$state.ready"
        while [[ ! -e "$state.trigger" ]]; do
            sleep 0.05
        done
        kill -SEGV "$BASHPID"
    ) &

    while :; do
        sleep 3600 &
        wait "$!" || :
    done
fi

: >"$state.ready"
if [[ "$mode" == idle ]]; then
    exec /usr/bin/sleep infinity
fi

printf -v dirty '%*s' $((8 * 1024 * 1024)) x
while [[ ! -e "$state.trigger" ]]; do
    :
done
kill -SEGV "$$"
EOF
chmod +x "$helper"

cat >"$dbus_helper" <<'EOF'
#!/usr/bin/env python3
import ctypes
import os
import signal
import sys
import time

state, bus_name = sys.argv[1:]
generation = 0
try:
    with open(state + ".generation", encoding="utf-8") as f:
        generation = int(f.read())
except FileNotFoundError:
    pass
generation += 1
with open(state + ".generation", "w", encoding="utf-8") as f:
    f.write(f"{generation}\n")
with open(f"{state}.pid.{generation}", "w", encoding="utf-8") as f:
    f.write(f"{os.getpid()}\n")

libsystemd = ctypes.CDLL("libsystemd.so.0")
bus = ctypes.c_void_p()
libsystemd.sd_bus_default_system.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
libsystemd.sd_bus_default_system.restype = ctypes.c_int
libsystemd.sd_bus_request_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64]
libsystemd.sd_bus_request_name.restype = ctypes.c_int
if libsystemd.sd_bus_default_system(ctypes.byref(bus)) < 0:
    raise RuntimeError("failed to connect to the system bus")
if libsystemd.sd_bus_request_name(bus, bus_name.encode(), 0) < 0:
    raise RuntimeError("failed to acquire the service bus name")

open(state + ".ready", "w", encoding="utf-8").close()
if generation > 1:
    while True:
        time.sleep(3600)

dirty = bytearray(8 * 1024 * 1024)
while not os.path.exists(state + ".trigger"):
    time.sleep(0.05)
os.kill(os.getpid(), signal.SIGSEGV)
EOF
chmod +x "$dbus_helper"

# Give this deliberate Python coredump a test-specific executable name, so the TEST-87 wrapper can
# distinguish it from unexpected Python crashes elsewhere in the test.
cp --dereference --reflink=auto /usr/bin/python3 "$dbus_interpreter"

cat >"$receiver_dropin" <<EOF
[Service]
ExecStartPre=/bin/bash -c 'touch "$receiver_ready"; while [[ ! -e "$receiver_release" ]]; do sleep 0.05; done'
EOF

cat >"/run/systemd/system/$worker_unit" <<EOF
[Service]
Type=exec
ExecStart=$helper $worker_state worker
RestartDuringCoredump=yes
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

cat >"/run/systemd/system/$dbus_unit" <<EOF
[Service]
Type=dbus
BusName=$bus_name
ExecStart=$dbus_interpreter $dbus_helper $dbus_state $bus_name
RestartDuringCoredump=yes
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

cat >"/run/systemd/system/$manual_unit" <<EOF
[Service]
Type=exec
ExecStart=$helper $manual_state plain
ExecStop=/bin/bash -c 'touch "$manual_state.stop-pending"; while [[ ! -e "$manual_stop_release" ]]; do sleep 0.05; done'
RestartDuringCoredump=yes
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

cat >"/run/systemd/system/$limit_unit" <<EOF
[Unit]
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=exec
ExecStart=$helper $limit_state plain
RestartDuringCoredump=yes
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

cat >"/run/systemd/system/$forge_unit" <<EOF
[Service]
Type=exec
ExecStart=$helper $forge_state idle
RestartDuringCoredump=yes
Restart=on-failure
RestartSec=0
LimitCORE=infinity
EOF

systemctl daemon-reload
systemctl start "${units[@]}"
timeout 30 bash -c "until [[ -e '$worker_state.ready' && -e '$dbus_state.ready' && -e '$manual_state.ready' && -e '$limit_state.ready' && -e '$forge_state.ready' ]]; do sleep 0.05; done"

worker_main="$(<"$worker_state.pid.1")"
worker_pid="$(<"$worker_state.worker")"
dbus_pid="$(<"$dbus_state.pid.1")"
manual_pid="$(<"$manual_state.pid.1")"
limit_pid="$(<"$limit_state.pid.1")"
forge_pid="$(<"$forge_state.pid.1")"
worker_invocation="$(systemctl show -P InvocationID "$worker_unit")"
dbus_invocation="$(systemctl show -P InvocationID "$dbus_unit")"
manual_invocation="$(systemctl show -P InvocationID "$manual_unit")"
forge_invocation="$(systemctl show -P InvocationID "$forge_unit")"

# A non-root process can obtain and pass a pidfd, but its forged coredump message must be ignored.
NOTIFY_SOCKET=/run/systemd/notify \
    setpriv --reuid=65534 --regid=65534 --clear-groups /usr/bin/python3 - "$forge_pid" <<'PY'
import os
import sys

fd = os.pidfd_open(int(sys.argv[1]))
if fd != 3:
    os.dup2(fd, 3)
    os.close(fd)
os.set_inheritable(3, True)
os.execv(
    "/usr/bin/systemd-notify",
    [
        "systemd-notify",
        "--no-block",
        "--fd=3",
        "X_SYSTEMD_COREDUMP=1",
        "X_SYSTEMD_COREDUMP_SIGNAL=11",
    ],
)
PY
sleep 0.5
[[ "$(systemctl show -P MainPID "$forge_unit")" -eq "$forge_pid" ]]
[[ "$(systemctl show -P InvocationID "$forge_unit")" == "$forge_invocation" ]]
[[ "$(systemctl show -P NRestarts "$forge_unit")" -eq 0 ]]
systemctl --quiet is-active "$forge_unit"

# Queue an explicit stop and hold ExecStop= before crashing the main process.
systemctl stop --no-block "$manual_unit"
timeout 30 bash -c "until [[ -e '$manual_state.stop-pending' ]]; do sleep 0.05; done"
[[ "$(systemctl show -P ActiveState "$manual_unit")" == deactivating ]]

: >"$worker_state.trigger"
: >"$dbus_state.trigger"
: >"$manual_state.trigger"
: >"$limit_state.trigger"

timeout 30 bash -c "until [[ -e '$receiver_ready' ]]; do sleep 0.05; done"
wait_for_core "$worker_pid"
wait_for_core "$dbus_pid"
wait_for_core "$manual_pid"
wait_for_core "$limit_pid"

# A worker dump is unrelated to the service's main process.
[[ "$(systemctl show -P MainPID "$worker_unit")" -eq "$worker_main" ]]
[[ "$(systemctl show -P InvocationID "$worker_unit")" == "$worker_invocation" ]]
[[ "$(systemctl show -P NRestarts "$worker_unit")" -eq 0 ]]
systemctl --quiet is-active "$worker_unit"

# Type=dbus is deliberately ineligible for the early path.
[[ "$(systemctl show -P MainPID "$dbus_unit")" -eq "$dbus_pid" ]]
[[ "$(systemctl show -P InvocationID "$dbus_unit")" == "$dbus_invocation" ]]
[[ "$(systemctl show -P NRestarts "$dbus_unit")" -eq 0 ]]
systemctl --quiet is-active "$dbus_unit"

# A pending manual stop wins over Restart= while the main process is dumping.
[[ "$(systemctl show -P MainPID "$manual_unit")" -eq "$manual_pid" ]]
[[ "$(systemctl show -P InvocationID "$manual_unit")" == "$manual_invocation" ]]
[[ "$(systemctl show -P NRestarts "$manual_unit")" -eq 0 ]]
[[ "$(systemctl show -P ActiveState "$manual_unit")" == deactivating ]]

# The early path schedules the normal restart job, which is rejected by the start limiter.
timeout 30 bash -c "until [[ \$(systemctl show -P Result '$limit_unit') == start-limit-hit ]]; do sleep 0.05; done"
[[ "$(systemctl show -P ActiveState "$limit_unit")" == failed ]]
[[ "$(systemctl show -P NRestarts "$limit_unit")" -eq 1 ]]
[[ ! -e "$limit_state.pid.2" ]]
grep '^CoreDumping:[[:space:]]*1$' "/proc/$limit_pid/status" >/dev/null

: >"$receiver_release"
timeout 60 bash -c 'while systemctl --quiet is-active "systemd-coredump@*.service"; do sleep 0.1; done'
timeout 60 bash -c "until [[ ! -e '/proc/$worker_pid' && ! -e '/proc/$dbus_pid' && ! -e '/proc/$manual_pid' && ! -e '/proc/$limit_pid' ]]; do sleep 0.1; done"

# Reaping a worker leaves the running main generation untouched.
[[ "$(systemctl show -P MainPID "$worker_unit")" -eq "$worker_main" ]]
[[ "$(systemctl show -P InvocationID "$worker_unit")" == "$worker_invocation" ]]
[[ "$(systemctl show -P NRestarts "$worker_unit")" -eq 0 ]]
systemctl --quiet is-active "$worker_unit"

# Type=dbus restarts only after the real SIGCHLD and bus-name release.
wait_for_restart "$dbus_unit"
[[ "$(systemctl show -P MainPID "$dbus_unit")" -eq "$(<"$dbus_state.pid.2")" ]]
[[ "$(systemctl show -P MainPID "$dbus_unit")" -ne "$dbus_pid" ]]
[[ "$(systemctl show -P InvocationID "$dbus_unit")" != "$dbus_invocation" ]]
systemctl --quiet is-active "$dbus_unit"

# Completing the explicit stop cannot schedule a restart retroactively.
: >"$manual_stop_release"
timeout 30 bash -c "until [[ \$(systemctl show -P ActiveState '$manual_unit') != deactivating ]]; do sleep 0.05; done"
[[ "$(systemctl show -P ActiveState "$manual_unit")" == failed ]]
[[ "$(systemctl show -P NRestarts "$manual_unit")" -eq 0 ]]
[[ ! -e "$manual_state.pid.2" ]]

# Reaping the retired start-limited process does not cause another attempt.
[[ "$(systemctl show -P ActiveState "$limit_unit")" == failed ]]
[[ "$(systemctl show -P Result "$limit_unit")" == start-limit-hit ]]
[[ "$(systemctl show -P NRestarts "$limit_unit")" -eq 1 ]]
[[ ! -e "$limit_state.pid.2" ]]

systemctl stop "$worker_unit" "$dbus_unit" "$forge_unit"
