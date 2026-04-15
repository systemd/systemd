#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Exercise io.systemd.QemuMachineInstance.AcquireQMP — the protocol upgrade that
# hands a varlink caller a native QMP stream multiplexed over vmspawn's shared
# QmpClient.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which doesn't work under ASan, skipping"
    exit 0
fi

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping"
    exit 0
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 0
fi

if ! command -v virtiofsd >/dev/null 2>&1 &&
   ! test -x /usr/libexec/virtiofsd &&
   ! test -x /usr/lib/virtiofsd; then
    echo "virtiofsd not found, skipping"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found, skipping"
    exit 0
fi

KERNEL=""
for k in /usr/lib/modules/"$(uname -r)"/vmlinuz /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz; do
    if [[ -f "$k" ]]; then
        KERNEL="$k"
        break
    fi
done
if [[ -z "$KERNEL" ]]; then
    echo "No kernel found for direct VM boot, skipping"
    exit 0
fi
echo "Using kernel: $KERNEL"

MACHINE="test-vmspawn-acquire-qmp-$$"
WORKDIR="$(mktemp -d)"

at_exit() {
    set +e
    if machinectl status "$MACHINE" &>/dev/null; then
        machinectl terminate "$MACHINE" 2>/dev/null
        timeout 10 bash -c "while machinectl status '$MACHINE' &>/dev/null; do sleep .5; done" 2>/dev/null
    fi
    [[ -n "${VMSPAWN_PID:-}" ]] && kill "$VMSPAWN_PID" 2>/dev/null && wait "$VMSPAWN_PID" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

mkdir -p "$WORKDIR/root/sbin"
cat >"$WORKDIR/root/sbin/init" <<'EOF'
#!/bin/sh
exec sleep infinity
EOF
chmod +x "$WORKDIR/root/sbin/init"

wait_for_machine() {
    local machine="$1" pid="$2" log="$3"
    timeout 30 bash -c "
        while ! machinectl list --no-legend 2>/dev/null | grep >/dev/null '$machine'; do
            if ! kill -0 $pid 2>/dev/null; then
                if grep >/dev/null 'virtiofs.*QMP\|vhost-user-fs-pci' '$log'; then
                    echo 'vhost-user-fs not supported (nested VM?), skipping'
                    exit 77
                fi
                echo 'vmspawn exited before registering'
                cat '$log'
                exit 1
            fi
            sleep .5
        done
    " || {
        local rc=$?
        if [[ $rc -eq 77 ]]; then exit 0; fi
        exit "$rc"
    }
}

systemd-vmspawn \
    --machine="$MACHINE" \
    --ram=256M \
    --directory="$WORKDIR/root" \
    --linux="$KERNEL" \
    --tpm=no \
    --console=headless \
    &>"$WORKDIR/vmspawn.log" &
VMSPAWN_PID=$!

wait_for_machine "$MACHINE" "$VMSPAWN_PID" "$WORKDIR/vmspawn.log"
echo "Machine '$MACHINE' registered with machined"

VARLINK_ADDR=$(varlinkctl call /run/systemd/machine/io.systemd.Machine \
    io.systemd.Machine.List "{\"name\":\"$MACHINE\"}" | jq -r '.controlAddress')
assert_neq "$VARLINK_ADDR" "null"

# Python QMP-upgrade client. Takes the varlink socket path as argv[1], the
# scenario name as argv[2], and any scenario-specific args after. Prints "ok"
# on success and exits 0; otherwise prints a diagnostic and exits non-zero.
cat >"$WORKDIR/acquire-qmp.py" <<'PY'
#!/usr/bin/env python3
"""AcquireQMP upgrade client used by TEST-87-AUX-UTILS-VM.vmspawn-acquire-qmp.sh."""

import json
import os
import socket
import sys
import time


def connect_and_upgrade(addr):
    """Open the varlink socket, issue AcquireQMP with upgrade:true, verify the
    reply, and return the connected socket already in raw-QMP mode."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(addr)
    req = {
        "method": "io.systemd.QemuMachineInstance.AcquireQMP",
        "upgrade": True,
    }
    s.sendall(json.dumps(req).encode() + b"\x00")
    # Read the varlink reply (single JSON object terminated by NUL).
    buf = b""
    while b"\x00" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed before varlink reply arrived")
        buf += chunk
    reply_raw, _, rest = buf.partition(b"\x00")
    reply = json.loads(reply_raw)
    if "error" in reply:
        raise RuntimeError(f"AcquireQMP returned error: {reply}")
    return s, rest


def read_qmp_line(s, buffered, timeout=10.0):
    """Read one CRLF-terminated JSON message from the raw QMP stream. `buffered`
    is any bytes pre-read from the last recv. Returns (json_obj, leftover)."""
    deadline = time.monotonic() + timeout
    while b"\r\n" not in buffered:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"no CRLF in: {buffered!r}")
        s.settimeout(remaining)
        chunk = s.recv(4096)
        if not chunk:
            raise EOFError("QMP stream closed")
        buffered += chunk
    line, _, rest = buffered.partition(b"\r\n")
    return json.loads(line), rest


def expect_greeting(s, buffered):
    obj, buffered = read_qmp_line(s, buffered)
    if "QMP" not in obj:
        raise RuntimeError(f"expected greeting, got {obj}")
    return buffered


def negotiate(s, buffered, caller_id=42):
    """Send qmp_capabilities, verify the short-circuit reply carries caller_id
    back. Returns buffered bytes following the reply."""
    s.sendall(
        json.dumps({"execute": "qmp_capabilities", "id": caller_id}).encode() + b"\r\n"
    )
    reply, buffered = read_qmp_line(s, buffered)
    if reply != {"return": {}, "id": caller_id}:
        raise RuntimeError(f"bad qmp_capabilities reply: {reply}")
    return buffered


def scenario_single(addr):
    s, buffered = connect_and_upgrade(addr)
    buffered = expect_greeting(s, buffered)
    buffered = negotiate(s, buffered, caller_id=42)

    # Use a non-integer id on purpose — QMP allows any JSON value there and we
    # must preserve the exact variant round-trip.
    s.sendall(json.dumps({"execute": "query-status", "id": "abc"}).encode() + b"\r\n")
    reply, buffered = read_qmp_line(s, buffered)
    assert reply.get("id") == "abc", f"id mismatch: {reply}"
    assert reply["return"]["running"] is True, f"unexpected return: {reply}"
    print("ok")


def scenario_collision(addr):
    """Two acquirers both send id=1; each must get id=1 back in its own reply."""
    a, ba = connect_and_upgrade(addr)
    b, bb = connect_and_upgrade(addr)
    ba = expect_greeting(a, ba)
    bb = expect_greeting(b, bb)
    ba = negotiate(a, ba, caller_id=99)
    bb = negotiate(b, bb, caller_id=99)

    for sk, name in ((a, "A"), (b, "B")):
        sk.sendall(json.dumps({"execute": "query-status", "id": 1}).encode() + b"\r\n")

    rep_a, ba = read_qmp_line(a, ba)
    rep_b, bb = read_qmp_line(b, bb)
    assert rep_a.get("id") == 1, f"A id mismatch: {rep_a}"
    assert rep_b.get("id") == 1, f"B id mismatch: {rep_b}"
    assert rep_a["return"]["running"] is True
    assert rep_b["return"]["running"] is True
    print("ok")


def scenario_pre_cap_rejected(addr):
    """Mirrors QEMU's monitor/qmp.c semantics: a well-formed execute=<cmd> or
    exec-oob=<cmd> sent before qmp_capabilities completes gets CommandNotFound
    back with the QEMU-standard desc 'Expecting capabilities negotiation with
    qmp_capabilities'."""
    s, buffered = connect_and_upgrade(addr)
    buffered = expect_greeting(s, buffered)
    # Skip qmp_capabilities, send a regular command.
    s.sendall(json.dumps({"execute": "query-status", "id": 7}).encode() + b"\r\n")
    reply, buffered = read_qmp_line(s, buffered)
    err = reply.get("error") or {}
    assert err.get("class") == "CommandNotFound", f"bad reject: {reply}"
    assert "qmp_capabilities" in err.get("desc", ""), f"bad desc: {reply}"
    assert reply.get("id") == 7, f"id not preserved: {reply}"
    print("ok")


def scenario_missing_id(addr):
    s, buffered = connect_and_upgrade(addr)
    buffered = expect_greeting(s, buffered)
    buffered = negotiate(s, buffered, caller_id=11)

    # No id field — response must be dropped.
    s.sendall(json.dumps({"execute": "query-status"}).encode() + b"\r\n")
    # Follow-up with an id so we can bound the wait.
    s.sendall(json.dumps({"execute": "query-status", "id": 22}).encode() + b"\r\n")
    reply, buffered = read_qmp_line(s, buffered)
    assert reply.get("id") == 22, f"got unexpected reply {reply}; the id-less one may have leaked"
    print("ok")


def scenario_event(addr):
    """After negotiation, expect QMP events to flow through the proxy. The
    shell script triggers a STOP by calling MachineInstance.Pause separately.
    This scenario just waits for a STOP event on the raw stream."""
    s, buffered = connect_and_upgrade(addr)
    buffered = expect_greeting(s, buffered)
    buffered = negotiate(s, buffered, caller_id=1)

    # Tell the shell script that we are ready to receive events. The 'ready'
    # sentinel line is written to stdout and the shell waits for it before
    # triggering the pause.
    print("ready", flush=True)

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        obj, buffered = read_qmp_line(s, buffered, timeout=deadline - time.monotonic())
        if obj.get("event") == "STOP":
            print("ok")
            return
    raise TimeoutError("STOP event not seen")


def scenario_pre_handshake_drop(addr):
    """Mirrors QEMU's monitor behaviour: events are not delivered to an acquirer that
    hasn't yet sent qmp_capabilities."""
    s, buffered = connect_and_upgrade(addr)
    buffered = expect_greeting(s, buffered)

    # Signal readiness; shell triggers a STOP now.
    print("ready", flush=True)

    # Read for ~2 seconds. A pre-handshake acquirer must NOT see STOP.
    s.settimeout(2)
    try:
        chunk = s.recv(4096)
        if chunk:
            more_bytes = buffered + chunk
            while b"\r\n" in more_bytes:
                line, _, more_bytes = more_bytes.partition(b"\r\n")
                obj = json.loads(line)
                if obj.get("event"):
                    raise RuntimeError(f"unexpected event pre-negotiation: {obj}")
    except (TimeoutError, socket.timeout):
        pass  # expected: nothing arrives pre-negotiation

    print("ok")


def scenario_eof(addr):
    s, buffered = connect_and_upgrade(addr)
    buffered = expect_greeting(s, buffered)
    buffered = negotiate(s, buffered, caller_id=1)

    print("ready", flush=True)

    # Read until EOF (signalled by empty recv after QEMU dies).
    deadline = time.monotonic() + 15
    s.settimeout(deadline - time.monotonic())
    try:
        while time.monotonic() < deadline:
            chunk = s.recv(4096)
            if not chunk:
                print("ok")
                return
            buffered += chunk
    except (TimeoutError, socket.timeout):
        pass
    raise TimeoutError("EOF not observed after QEMU terminate")


SCENARIOS = {
    "single": scenario_single,
    "collision": scenario_collision,
    "pre_cap_rejected": scenario_pre_cap_rejected,
    "missing_id": scenario_missing_id,
    "event": scenario_event,
    "pre_handshake_drop": scenario_pre_handshake_drop,
    "eof": scenario_eof,
}


if __name__ == "__main__":
    addr = sys.argv[1]
    name = sys.argv[2]
    SCENARIOS[name](addr)
PY
chmod +x "$WORKDIR/acquire-qmp.py"

run_scenario() {
    local name="$1"
    local out
    out=$(python3 "$WORKDIR/acquire-qmp.py" "$VARLINK_ADDR" "$name")
    assert_in "ok" "$out"
    echo "AcquireQMP scenario '$name' passed"
}

# --- Scenario 1: single acquirer round-trips greeting + caps + query-status ---
run_scenario single

# --- Scenario 2: two acquirers with colliding ids ---
run_scenario collision

# --- Scenario 3: pre-cap command gets CommandNotFound with the QEMU-standard desc ---
run_scenario pre_cap_rejected

# --- Scenario 4: commands without an id are forwarded but the response is dropped ---
run_scenario missing_id

# --- Scenario 5: events flow after cap negotiation ---
# The python helper prints 'ready' once it's ready to receive events; we wait for
# that marker, trigger a pause, then wait for the helper to exit.
( python3 "$WORKDIR/acquire-qmp.py" "$VARLINK_ADDR" event >"$WORKDIR/event.out" 2>"$WORKDIR/event.err" ) &
EVENT_PID=$!
timeout 5 bash -c "until grep >/dev/null '^ready' '$WORKDIR/event.out'; do sleep 0.1; done"
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Pause '{}'
wait "$EVENT_PID"
grep >/dev/null '^ok' "$WORKDIR/event.out"
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Resume '{}'
echo "AcquireQMP scenario 'event' passed"

# --- Scenario 6: pre-handshake acquirer does NOT see events ---
( python3 "$WORKDIR/acquire-qmp.py" "$VARLINK_ADDR" pre_handshake_drop >"$WORKDIR/drop.out" 2>"$WORKDIR/drop.err" ) &
DROP_PID=$!
timeout 5 bash -c "until grep >/dev/null '^ready' '$WORKDIR/drop.out'; do sleep 0.1; done"
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Pause '{}'
wait "$DROP_PID"
grep >/dev/null '^ok' "$WORKDIR/drop.out"
varlinkctl call "$VARLINK_ADDR" io.systemd.MachineInstance.Resume '{}'
echo "AcquireQMP scenario 'pre_handshake_drop' passed"

# --- Scenario 7: acquirer sees EOF when QEMU terminates ---
( python3 "$WORKDIR/acquire-qmp.py" "$VARLINK_ADDR" eof >"$WORKDIR/eof.out" 2>"$WORKDIR/eof.err" ) &
EOF_PID=$!
timeout 5 bash -c "until grep >/dev/null '^ready' '$WORKDIR/eof.out'; do sleep 0.1; done"
machinectl terminate "$MACHINE"
wait "$EOF_PID"
grep >/dev/null '^ok' "$WORKDIR/eof.out"
echo "AcquireQMP scenario 'eof' passed"

# VMSPAWN_PID exited when machinectl terminate ran; prevent at_exit from waiting on it.
VMSPAWN_PID=""

echo "All AcquireQMP upgrade tests passed"
