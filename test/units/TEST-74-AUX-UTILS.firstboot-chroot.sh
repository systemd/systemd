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
SERVER_INDEX=0
CLIENT_UNITS=()

at_exit() {
    set +e
    if [[ ${#CLIENT_UNITS[@]} -gt 0 ]]; then
        systemctl stop "${CLIENT_UNITS[@]}"
    fi
    [[ -n "$SERVER_UNIT" ]] && systemctl stop "$SERVER_UNIT.service"
    rm -rf "$WORK"
}
trap at_exit EXIT

mkdir -p "$WORK/sockets" "$WORK/offline"
touch "$WORK/requests"

start_server() {
    local response="$1"

    [[ -z "$SERVER_UNIT" ]] || systemctl stop "$SERVER_UNIT.service"
    SERVER_INDEX=$((SERVER_INDEX + 1))
    SERVER_UNIT="$UNIT-server-$SERVER_INDEX"
    rm -f "$WORK/sockets/io.systemd.Hostname"
    # shellcheck disable=SC2016
    systemd-run --collect --unit="$SERVER_UNIT" -p Type=notify \
        -p TimeoutStartSec=15 -p RuntimeMaxSec=120 \
        systemd-socket-activate --accept --inetd -l "$WORK/sockets/io.systemd.Hostname" \
        timeout 10 "$BASH_BIN" -euc '
            IFS= read -r -d "" request
            printf "%s\n" "$request" >>"$1"
            printf "%s\0" "$2"
        ' bash "$WORK/requests" "$response"
}

run_client() {
    local name="$1" etc="$2"
    shift 2
    CLIENT_UNITS+=("$UNIT-$name.service")

    systemd-run --wait --pipe --collect --unit="$UNIT-$name" \
        -p Type=exec -p ProtectHostname=yes -p BindLogSockets=no -p RuntimeMaxSec=30 \
        -p "BindPaths=$etc:/etc $WORK/sockets:/run/systemd" \
        --setenv=SYSTEMD_LOG_TARGET=console "$@"
}

assert_no_requests() {
    if [[ -s "$WORK/requests" ]]; then
        cat "$WORK/requests"
        echo "FAIL: firstboot contacted hostnamed from a chroot" >&2
        exit 1
    fi
    if [[ "${1:-true}" == true ]]; then
        systemctl is-active "$SERVER_UNIT.service"
    fi
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
run_client live "$WORK/live-etc" "$FIRSTBOOT" --hostname=firstboot-live
assert_request firstboot-live
[[ ! -e "$WORK/live-etc/hostname" ]]

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
    run_client "$name" "$WORK/$name/etc" "${properties[@]}" "$BASH_BIN" -euc '
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
run_client offline "$WORK/offline-etc" "$FIRSTBOOT" --root="$WORK/offline" --hostname=firstboot-offline
assert_no_requests
assert_eq "$(cat "$WORK/offline/etc/hostname")" "firstboot-offline"

# An indeterminate chroot check must not contact a potentially foreign hostnamed.
: >"$WORK/requests"
mkdir "$WORK/unknown-etc" "$WORK/hidden-pid1"
CLIENT_UNITS+=("$UNIT-unknown.service")
# shellcheck disable=SC2016
systemd-run --wait --pipe --collect --unit="$UNIT-unknown" \
    -p Type=exec -p ProtectHostname=yes -p BindLogSockets=no -p RuntimeMaxSec=30 \
    -p "BindPaths=$WORK/unknown-etc:/etc $WORK/sockets:/run/systemd $WORK/hidden-pid1:/proc/1" \
    --setenv=SYSTEMD_LOG_TARGET=console "$BASH_BIN" -euc '
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
run_client unsupported "$WORK/unsupported-etc" "$FIRSTBOOT" --hostname=firstboot-unsupported
assert_request firstboot-unsupported
assert_eq "$(cat "$WORK/unsupported-etc/hostname")" "firstboot-unsupported"

systemctl stop "$SERVER_UNIT.service"
rm -f "$WORK/sockets/io.systemd.Hostname"
: >"$WORK/requests"
mkdir "$WORK/no-socket-etc"
run_client no-socket "$WORK/no-socket-etc" "$FIRSTBOOT" --hostname=firstboot-no-socket
assert_no_requests false
assert_eq "$(cat "$WORK/no-socket-etc/hostname")" "firstboot-no-socket"
