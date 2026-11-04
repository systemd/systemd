#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Regression test for daemon-reexec preparation failures. If reexecution fails
# before execve(), the nested manager must keep running and report the request
# failure to the D-Bus or varlink client instead of letting disconnect stand in
# for successful reexecution.

if [[ -x /usr/lib/systemd/systemd ]]; then
    SYSTEMD_BIN=/usr/lib/systemd/systemd
elif [[ -x /lib/systemd/systemd ]]; then
    SYSTEMD_BIN=/lib/systemd/systemd
else
    echo "Cannot find systemd binary"
    exit 77
fi

systemctl start user@0.service

export SYSTEMD_BIN
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/0}"

systemd-run --user --pipe --wait --collect \
    -p Delegate=yes \
    -p Type=exec \
    -E SYSTEMD_BIN="$SYSTEMD_BIN" \
    bash -s <<'REPRO'
set -eux
set -o pipefail

systemd_bin=${SYSTEMD_BIN:?}
units_dir=$(mktemp -d /tmp/systemd-reexec-units.XXXXXX)

cleanup_units() {
    rm -rf "$units_dir"
}
trap cleanup_units EXIT

cp /usr/lib/systemd/user/{basic,default,exit,paths,shutdown,sockets,timers}.target \
   /usr/lib/systemd/user/systemd-exit.service "$units_dir/"

run_one() {
    local transport=${1:?}
    local headroom=${2:?}
    local run_dir log_file out_file status

    run_dir=$(mktemp -d /tmp/systemd-reexec.XXXXXX) || exit 1
    log_file="$run_dir/manager.log"
    out_file="$run_dir/client.out"
    chmod 700 "$run_dir"

    echo "CASE transport=$transport headroom=$headroom"

    set +e
    timeout 18 env -u DBUS_SESSION_BUS_ADDRESS \
        RUN_DIR="$run_dir" \
        LOG_FILE="$log_file" \
        OUT_FILE="$out_file" \
        SYSTEMD_BIN="$systemd_bin" \
        HEADROOM="$headroom" \
        TRANSPORT="$transport" \
        UNIT_DIR="$units_dir" \
        XDG_RUNTIME_DIR="$run_dir" \
        bash <<'INNER'
set -u
export XDG_RUNTIME_DIR="$RUN_DIR"
export SYSTEMD_UNIT_PATH="$UNIT_DIR"

pid=
cleanup() {
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

SYSTEMD_LOG_LEVEL=debug SYSTEMD_LOG_TARGET=console "$SYSTEMD_BIN" --user >"$LOG_FILE" 2>&1 &
pid=$!

ready=no
for _ in $(seq 1 240); do
    if [ -S "$XDG_RUNTIME_DIR/systemd/private" ] &&
        [ -S "$XDG_RUNTIME_DIR/systemd/io.systemd.Manager" ] &&
        grep 'Startup finished' "$LOG_FILE" >/dev/null 2>&1; then
        ready=yes
        break
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done

if [ "$ready" != yes ]; then
    echo "ready=no pid=$pid"
    sed -n '1,120p' "$LOG_FILE"
    exit 1
fi

before=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
limit=$((before + HEADROOM))
prlimit --pid "$pid" --nofile="$limit:$limit"

status=0
if [ "$TRANSPORT" = varlink ]; then
    timeout 10 varlinkctl call "$XDG_RUNTIME_DIR/systemd/io.systemd.Manager" io.systemd.Manager.Reexecute '{}' >"$OUT_FILE" 2>&1 || status=$?
else
    timeout 10 systemctl --user daemon-reexec >"$OUT_FILE" 2>&1 || status=$?
fi

sleep 0.8
if kill -0 "$pid" 2>/dev/null; then alive=yes; else alive=no; fi
echo "before=$before limit=$limit client_status=$status manager_alive_after=$alive"

if [ -s "$OUT_FILE" ]; then
    sed 's/^/client: /' "$OUT_FILE"
fi

if [ "$status" -ne 0 ] && [ "$alive" = yes ] &&
    grep -E 'Too many open files|System.Error.EMFILE' "$OUT_FILE" >/dev/null 2>&1 &&
    grep -E 'Reexecution requested|Reexecute requested' "$LOG_FILE" >/dev/null 2>&1 &&
    grep 'Failed to prepare for reexecution, continuing' "$LOG_FILE" >/dev/null 2>&1; then
    second_limit=$((before + HEADROOM + 256))
    second_out="$RUN_DIR/second.out"
    prlimit --pid "$pid" --nofile="$second_limit:$second_limit"

    second_status=0
    timeout 10 systemctl --user daemon-reexec >"$second_out" 2>&1 || second_status=$?

    sleep 0.8
    if kill -0 "$pid" 2>/dev/null; then second_alive=yes; else second_alive=no; fi
    echo "second_limit=$second_limit second_status=$second_status manager_alive_after_second=$second_alive"

    if [ -s "$second_out" ]; then
        sed 's/^/second-client: /' "$second_out"
    fi

    if [ "$second_status" -eq 0 ] && [ "$second_alive" = yes ] &&
        grep 'Reexecuting.' "$LOG_FILE" >/dev/null 2>&1; then
        exit 0
    fi
fi

exit 1
INNER
    status=$?
    set -e

    if [[ -s "$log_file" ]]; then
        sed -n \
            '/Got message.*Reexecute/p;
             /varlink.*Reexecute/p;
             /Reexecute requested/p;
             /Reexecution requested/p;
             /Reexecuting[.]/p;
             /Failed to prepare for reexecution/p;
             /Failed to create serialization/p;
             /Failed to add bus sockets/p;
             /Failed to add file descriptor/p;
             /Failed to serialize/p;
             /Too many open files/p;
             /Failed to accept private connection/p;
             /Sent message type=error/p;
             /io.systemd.System/p' "$log_file"
    fi

    chmod -R u+rwX "$run_dir" 2>/dev/null || true
    rm -rf "$run_dir" 2>/dev/null || true

    return "$status"
}

run_transport() {
    local transport=${1:?}
    local found=no
    local rc=0

    # Find the narrow fd headroom where the Reexecute request is accepted, but
    # prepare_reexecute() still runs out of descriptors during serialization.
    for headroom in $(seq 4 2 64); do
        rc=0
        run_one "$transport" "$headroom" || rc=$?
        if [[ "$rc" -eq 0 ]]; then
            found=yes
            break
        elif [[ "$rc" -eq 77 ]]; then
            echo "$transport transport is not available in the nested manager"
            return 77
        fi
    done

    if [[ "$found" != yes ]]; then
        echo "Failed to trigger recoverable prepare_reexecute() failure via $transport"
        return 1
    fi

    echo "Triggered recoverable prepare_reexecute() failure via $transport"
}

run_transport dbus
run_transport varlink
REPRO
