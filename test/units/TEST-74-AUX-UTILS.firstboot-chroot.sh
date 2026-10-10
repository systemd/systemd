#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 77
fi

FIRSTBOOT="$(readlink -f "$(command -v systemd-firstboot)")"
FIRSTBOOT_DIR="$(dirname "$FIRSTBOOT")"
BASH_BIN="$(readlink -f "$(command -v bash)")"
WORK="$(mktemp -d /tmp/firstboot-chroot.XXXXXX)"
UNIT="firstboot-chroot-${WORK##*.}"
SERVER_UNIT=""
BUS_PROBE_UNIT=""
CONSOLE_PROBE_UNITS=()
CONSOLE_NAMESPACE=""
SERVER_INDEX=0
CLIENT_UNITS=()

at_exit() {
    set +e
    if [[ ${#CLIENT_UNITS[@]} -gt 0 ]]; then
        systemctl stop "${CLIENT_UNITS[@]}"
    fi
    [[ -n "$BUS_PROBE_UNIT" ]] && systemctl stop "$BUS_PROBE_UNIT.service"
    if [[ ${#CONSOLE_PROBE_UNITS[@]} -gt 0 ]]; then
        systemctl stop "${CONSOLE_PROBE_UNITS[@]}"
    fi
    [[ -n "$SERVER_UNIT" ]] && systemctl stop "$SERVER_UNIT.service"
    rm -rf "$WORK"
}
trap at_exit EXIT

mkdir -p "$WORK/sockets/system" "$WORK/offline"
touch "$WORK/requests"

start_server() {
    local response="$1"

    [[ -z "$SERVER_UNIT" ]] || systemctl stop "$SERVER_UNIT.service"
    SERVER_INDEX=$((SERVER_INDEX + 1))
    SERVER_UNIT="$UNIT-server-$SERVER_INDEX"
    rm -f "$WORK/sockets/io.systemd.Hostname"
    # shellcheck disable=SC2016
    systemd-run --collect --unit="$SERVER_UNIT" -p Type=notify \
        -p TimeoutStartSec=15 \
        systemd-socket-activate --accept --inetd -l "$WORK/sockets/io.systemd.Hostname" \
        timeout 10 "$BASH_BIN" -euc '
            IFS= read -r -d "" request
            printf "%s\n" "$request" >>"$1"
            printf "%s\0" "$2"
        ' bash "$WORK/requests" "$response"
}

start_bus_probe() {
    BUS_PROBE_UNIT="$UNIT-bus-probe"
    rm -f "$WORK/sockets/private" "$WORK/bus-contact"
    # shellcheck disable=SC2016
    systemd-run --collect --unit="$BUS_PROBE_UNIT" -p Type=notify -p TimeoutStartSec=15 \
        systemd-socket-activate --accept --inetd -l "$WORK/sockets/private" \
        timeout 10 "$BASH_BIN" -euc 'printf "connected\n" >"$1"' bash "$WORK/bus-contact"
}

start_console_probes() {
    local anchor="$UNIT-console-namespace" pid

    CONSOLE_PROBE_UNITS+=("$anchor.service" "$UNIT-mute-probe.service" "$UNIT-plymouth-probe.service")
    systemd-run --collect --unit="$anchor" -p Type=exec -p PrivateNetwork=yes sleep infinity
    pid="$(systemctl show --property=MainPID --value "$anchor.service")"
    [[ "$pid" -gt 0 ]]
    CONSOLE_NAMESPACE="/proc/$pid/ns/net"

    # Isolate Plymouth's abstract socket from the host, but share it with the prompt clients.
    # shellcheck disable=SC2016
    systemd-run --collect --unit="$UNIT-plymouth-probe" -p Type=notify -p TimeoutStartSec=15 \
        -p "NetworkNamespacePath=$CONSOLE_NAMESPACE" \
        systemd-socket-activate --accept --inetd -l @/org/freedesktop/plymouthd \
        timeout 10 "$BASH_BIN" -euc '
            IFS= read -r -d "" request
            printf "%s\n" "$request" >"$1"
        ' bash "$WORK/plymouth-contact"

    # shellcheck disable=SC2016
    systemd-run --collect --unit="$UNIT-mute-probe" -p Type=notify -p TimeoutStartSec=15 \
        -p "NetworkNamespacePath=$CONSOLE_NAMESPACE" \
        systemd-socket-activate --accept --inetd -l "$WORK/sockets/io.systemd.MuteConsole" \
        timeout 10 "$BASH_BIN" -euc '
            IFS= read -r -d "" request
            printf "%s\n" "$request" >"$1"
            printf "%s\0" "{\"parameters\":{},\"continues\":true}"
            cat >/dev/null
        ' bash "$WORK/mute-contact"
}

wait_for_contact() {
    # shellcheck disable=SC2016
    timeout 10 "$BASH_BIN" -euc 'until [[ -s "$1" ]]; do sleep .1; done' bash "$1"
}

run_client() {
    local name="$1" etc="$2" extra_bind="$3"
    local bind_paths="$etc:/etc $WORK/sockets:/run/systemd"
    shift 3
    CLIENT_UNITS+=("$UNIT-$name.service")

    if [[ -n "$extra_bind" ]]; then
        bind_paths+=" $extra_bind"
    fi

    systemd-run --wait --pipe --collect --unit="$UNIT-$name" \
        -p Type=exec -p ProtectHostname=yes -p BindLogSockets=no -p RuntimeMaxSec=30 \
        -p "BindPaths=$bind_paths" \
        --setenv=SYSTEMD_LOG_TARGET=console "$@"
}

assert_no_requests() {
    if [[ -s "$WORK/requests" ]]; then
        cat "$WORK/requests"
        echo "FAIL: firstboot unexpectedly contacted hostnamed" >&2
        exit 1
    fi
    if [[ "${1:-true}" == true ]]; then
        systemctl is-active "$SERVER_UNIT.service"
    fi
}

assert_no_bus_contact() {
    systemctl is-active "$BUS_PROBE_UNIT.service"
    # Give asynchronously accepted requests time to become visible.
    # shellcheck disable=SC2016
    assert_rc 124 timeout 2 "$BASH_BIN" -euc '
        until [[ -e "$1" ]]; do sleep .1; done
    ' bash "$WORK/bus-contact"
    if [[ -e "$WORK/bus-contact" ]]; then
        echo "FAIL: firstboot unexpectedly contacted the system manager" >&2
        exit 1
    fi
    systemctl is-active "$BUS_PROBE_UNIT.service"
}

assert_console_probes_active() {
    local unit

    for unit in "${CONSOLE_PROBE_UNITS[@]}"; do
        systemctl is-active "$unit"
    done
}

assert_request() {
    local hostname="$1"

    assert_eq "$(wc -l <"$WORK/requests")" "1"
    systemctl is-active "$SERVER_UNIT.service"
    jq --exit-status --arg hostname "$hostname" \
        '.method == "io.systemd.Hostname.SetStaticHostname" and .parameters.newValue == $hostname' \
        "$WORK/requests"
}

start_server '{"parameters":{}}'

# A running system must still use hostnamed. The mock acknowledges the request without writing a file.
mkdir "$WORK/live-etc"
run_client live "$WORK/live-etc" "" "$FIRSTBOOT" --hostname=firstboot-live
assert_request firstboot-live
[[ ! -e "$WORK/live-etc/hostname" ]]

# An explicit false SYSTEMD_OFFLINE= overrides automatic chroot detection.
: >"$WORK/requests"
mkdir "$WORK/online-override-etc"
run_client online-override "$WORK/online-override-etc" "" \
    --setenv=SYSTEMD_OFFLINE=0 --setenv=SYSTEMD_IN_CHROOT=1 \
    "$FIRSTBOOT" --hostname=firstboot-online-override
assert_request firstboot-online-override
[[ ! -e "$WORK/online-override-etc/hostname" ]]

# SYSTEMD_OFFLINE= requests direct file writes and suppresses all host service calls.
: >"$WORK/requests"
mkdir "$WORK/offline-env-etc"
run_client offline-env "$WORK/offline-env-etc" "" --setenv=SYSTEMD_OFFLINE=1 \
    "$FIRSTBOOT" --hostname=firstboot-offline-env
assert_no_requests
assert_eq "$(cat "$WORK/offline-env-etc/hostname")" "firstboot-offline-env"

# Kernel command line modes still disable prompts when host-service calls are suppressed.
for mode in no headless; do
    for env in SYSTEMD_IN_CHROOT SYSTEMD_OFFLINE; do
        name="mode-$mode-$env"
        mkdir "$WORK/$name-etc"
        run_client "$name" "$WORK/$name-etc" "" \
            --setenv="$env=1" --setenv="SYSTEMD_PROC_CMDLINE=systemd.firstboot=$mode" \
            "$FIRSTBOOT" --prompt-hostname --welcome=no --chrome=no </dev/null
        assert_no_requests
        [[ ! -e "$WORK/$name-etc/hostname" ]]
    done
done

start_bus_probe
mkdir "$WORK/offline-reload-etc"
run_client offline-reload "$WORK/offline-reload-etc" "" --setenv=SYSTEMD_OFFLINE=1 \
    "$FIRSTBOOT" --locale=C.UTF-8
assert_no_bus_contact
grep -rFx "LANG=C.UTF-8" "$WORK/offline-reload-etc" >/dev/null

# The mock /run/systemd/system directory must let the online control reach the manager socket.
mkdir "$WORK/online-reload-etc"
run_client online-reload "$WORK/online-reload-etc" "" --setenv=SYSTEMD_OFFLINE=0 \
    "$FIRSTBOOT" --locale=C.UTF-8
wait_for_contact "$WORK/bus-contact"
grep -rFx "LANG=C.UTF-8" "$WORK/online-reload-etc" >/dev/null

# --root= still uses the host console, while offline host execution must not contact console services.
start_console_probes
for mode in root online offline chroot-env; do
    name="console-$mode"
    cmdline=""
    firstboot_options=()
    case "$mode" in
        root)
            mkdir -p "$WORK/$name-root/etc"
            firstboot_options=(--root="$WORK/$name-root")
            client_env=(--setenv=SYSTEMD_OFFLINE=0)
            # --root= ignores the host's firstboot mode and must still show the welcome and prompt.
            cmdline="systemd.firstboot=headless"
            ;;
        online)
            client_env=(--setenv=SYSTEMD_OFFLINE=0)
            ;;
        offline)
            client_env=(--setenv=SYSTEMD_OFFLINE=1)
            ;;
        chroot-env)
            client_env=(--setenv=SYSTEMD_IN_CHROOT=1)
            ;;
    esac
    rm -f "$WORK/mute-contact" "$WORK/plymouth-contact"
    mkdir "$WORK/$name-etc"
    assert_console_probes_active
    # A prompt with /dev/null input should fail on EOF, not wait until RuntimeMaxSec= kills the client.
    # shellcheck disable=SC2016
    run_client "$name" "$WORK/$name-etc" "" -p "NetworkNamespacePath=$CONSOLE_NAMESPACE" \
        "${client_env[@]}" --setenv="SYSTEMD_PROC_CMDLINE=$cmdline" --setenv=LC_ALL=C \
        "$BASH_BIN" -euc '
            firstboot="$1"
            log="$2"
            shift 2
            rc=0
            "$firstboot" "$@" --prompt-hostname --mute-console=yes --welcome=yes --chrome=no \
                </dev/null >"$log" 2>&1 || rc="$?"
            cat "$log"
            test "$rc" = 1
            grep -F "Failed to query user:" "$log" >/dev/null
            grep -F "Welcome to" "$log" >/dev/null
        ' bash "$FIRSTBOOT" "$WORK/$name.log" "${firstboot_options[@]}"
    assert_no_requests
    [[ ! -e "$WORK/$name-etc/hostname" ]]
    if [[ "$mode" == root ]]; then
        [[ ! -e "$WORK/$name-root/etc/hostname" ]]
    fi
    if [[ "$mode" == offline || "$mode" == chroot-env ]]; then
        # Plymouth does not await a reply. Give an asynchronously accepted request time to become visible.
        # shellcheck disable=SC2016
        assert_rc 124 timeout 2 "$BASH_BIN" -euc '
            until [[ -e "$1" || -e "$2" ]]; do sleep .1; done
        ' bash "$WORK/mute-contact" "$WORK/plymouth-contact"
        [[ ! -e "$WORK/mute-contact" && ! -e "$WORK/plymouth-contact" ]]
    else
        wait_for_contact "$WORK/mute-contact"
        wait_for_contact "$WORK/plymouth-contact"
        jq --exit-status '.method == "io.systemd.MuteConsole.Mute"' "$WORK/mute-contact"
        assert_eq "$(cat "$WORK/plymouth-contact")" H
    fi
    assert_console_probes_active
done

# Share only the mock socket with a real chroot. Check both the root and socket before firstboot runs.
for name in chroot chroot-env; do
    : >"$WORK/requests"
    mkdir -p "$WORK/$name/etc"
    properties=(-p "RootDirectory=$WORK/$name"
                -p "BindReadOnlyPaths=/usr /lib -/lib64 /proc $FIRSTBOOT_DIR" -p PrivateDevices=yes)
    if [[ "$name" == chroot-env ]]; then
        properties+=(--setenv=SYSTEMD_IN_CHROOT=1)
    fi
    # shellcheck disable=SC2016
    run_client "$name" "$WORK/$name/etc" "" "${properties[@]}" "$BASH_BIN" -euc '
        systemd-detect-virt --chroot
        test -S /run/systemd/io.systemd.Hostname
        exec "$1" --hostname=firstboot-chroot
    ' bash "$FIRSTBOOT"
    assert_no_requests
    assert_eq "$(cat "$WORK/$name/etc/hostname")" "firstboot-chroot"
done

# Explicit offline operation must also bypass the socket, even when it is reachable.
: >"$WORK/requests"
mkdir "$WORK/offline-etc"
run_client offline "$WORK/offline-etc" "" \
    "$FIRSTBOOT" --root="$WORK/offline" --hostname=firstboot-offline
assert_no_requests
assert_eq "$(cat "$WORK/offline/etc/hostname")" "firstboot-offline"

# An indeterminate chroot check must not contact a potentially foreign hostnamed.
: >"$WORK/requests"
mkdir "$WORK/unknown-etc" "$WORK/hidden-pid1"
# shellcheck disable=SC2016
run_client unknown "$WORK/unknown-etc" "$WORK/hidden-pid1:/proc/1" \
    --setenv=SYSTEMD_PROC_CMDLINE= "$BASH_BIN" -euc '
        test ! -e /proc/1/root
        test "$(stat -f -c %T /proc)" = proc
        exec "$1" --hostname=firstboot-unknown
    ' bash "$FIRSTBOOT"
assert_no_requests
assert_eq "$(cat "$WORK/unknown-etc/hostname")" "firstboot-unknown"

# Missing methods and missing sockets on a running system retain the direct-write fallback.
start_server '{"error":"org.varlink.service.MethodNotFound",
               "parameters":{"method":"io.systemd.Hostname.SetStaticHostname"}}'
: >"$WORK/requests"
mkdir "$WORK/unsupported-etc"
run_client unsupported "$WORK/unsupported-etc" "" "$FIRSTBOOT" --hostname=firstboot-unsupported
assert_request firstboot-unsupported
assert_eq "$(cat "$WORK/unsupported-etc/hostname")" "firstboot-unsupported"

systemctl stop "$SERVER_UNIT.service"
rm -f "$WORK/sockets/io.systemd.Hostname"
: >"$WORK/requests"
mkdir "$WORK/no-socket-etc"
run_client no-socket "$WORK/no-socket-etc" "" "$FIRSTBOOT" --hostname=firstboot-no-socket
assert_no_requests false
assert_eq "$(cat "$WORK/no-socket-etc/hostname")" "firstboot-no-socket"
