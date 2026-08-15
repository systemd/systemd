#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

export PAGER=

if [[ ! -f /usr/lib/systemd/user/systemd-appd.service ]]; then
    echo "systemd-appd is not installed, skipping."
    exit 77
fi

if ! cgroupfs_supports_user_xattrs; then
    echo "cgroupfs does not support user xattrs, skipping."
    exit 77
fi

TESTUSER_UID="$(id -u testuser)"
RUNTIME="/run/user/$TESTUSER_UID"
SOCK="$RUNTIME/systemd/io.systemd.AppInstance"

systemctl_user() {
    systemctl --user --machine "testuser@" "$@"
}

user_run_wait() {
    systemd-run --user --machine "testuser@" --pipe --wait --quiet -- "$@"
}

# Launches an "app" that does nothing in the background
start_bg_app() {
    local appid="${1:?}"
    local unit="app-${appid}.service"

    systemctl_user reset-failed "$unit" 2>/dev/null || true
    systemd-run --user --machine "testuser@" --quiet --unit="$unit" -p Type=notify -p NotifyAccess=all -- \
        bash -c 'systemd-notify --ready; exec sleep infinity' >&2
    systemctl_user show -P MainPID "$unit"
}

# Run a command as an app: registers with appd, then execs the command.
run_as_app() {
    local reg="${1:?}"; shift
    # Note that the exit status of systemd-run / user_run_wait becomes unreliable
    # after registration with appd, since appd moves the processes out of the
    # transient service and into a new transient .scope
    user_run_wait varlinkctl --exec call "$SOCK" io.systemd.AppInstance.Register "$reg" -- "$@" || true
}

# Call an appd method "as the app", and assert that it is refused with PermissionDenied
call_as_app_expect_denied() {
    local reg="${1:?}" method="${2:?}" params="${3:?}" out
    out="$(run_as_app "$reg" \
        env SYSTEMD_LOG_TARGET=console varlinkctl call \
            --graceful=org.varlink.service.PermissionDenied \
            "$SOCK" "$method" "$params" 2>&1)"
    grep "returned expected error: org.varlink.service.PermissionDenied" <<<"$out" >/dev/null
}

at_exit() {
    set +e

    systemctl_user stop appd-socktarget.service 2>/dev/null
    systemctl_user stop systemd-appd.service 2>/dev/null
    loginctl disable-linger testuser 2>/dev/null
}

trap at_exit EXIT

loginctl enable-linger testuser
systemctl start "user@$TESTUSER_UID.service"

systemctl_user reset-failed systemd-appd.service 2>/dev/null || true
systemctl_user start systemd-appd.service

# A plain unit whose name follows the app scheme is discovered by appd, and can be queried by PID.
testcase_01_systemd_run_query_by_pid() {
    local pid out
    pid="$(start_bg_app com.example.T1)"

    out="$(user_run_wait varlinkctl call --json=short "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.T1"

    kill "$pid" 2>/dev/null || true
}

# Registering moves the caller into a fresh app scope, and we can query the app
testcase_02_register_and_query_by_pid() {
    local pid out units pidfile
    pidfile="$RUNTIME/appd-pid-t2.$RANDOM"

    rm -f "$pidfile"
    # systemd-run collapses "$$" to "$", so we need "$$$$"
    systemd-run --user --machine "testuser@" --quiet -p Type=exec -- \
        varlinkctl --exec call "$SOCK" io.systemd.AppInstance.Register '{"id":"com.example.T2"}' -- \
            bash -c "echo \$\$\$\$ >'$pidfile'; exec sleep infinity" >&2
    timeout 60 bash -c "until [[ -s '$pidfile' ]]; do sleep 0.2; done"
    pid="$(cat "$pidfile")"

    out="$(user_run_wait varlinkctl call --json=short "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.T2"

    units="$(systemctl_user list-units --all --no-legend --plain || true)"
    grep -E 'app-com\.example\.T2-[0-9]+\.scope' <<<"$units" >/dev/null

    kill "$pid" 2>/dev/null || true
}

# A plainly registered app can query itself and gets its own data back (no sandbox set).
testcase_03_register_query_self() {
    local out
    out="$(run_as_app '{"id":"com.example.T3"}' \
        varlinkctl call --json=short "$SOCK" io.systemd.AppInstance.Query '{}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.T3"
    assert_eq "$(jq -r '.sandbox // "none"' <<<"$out")" "none"
}

# A sandboxed app is still allowed to query itself.
testcase_04_register_sandbox_query_self() {
    local out
    out="$(run_as_app '{"id":"com.example.T4","sandbox":"flatpak"}' \
        varlinkctl call --json=short "$SOCK" io.systemd.AppInstance.Query '{}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.T4"
    assert_eq "$(jq -r .sandbox <<<"$out")" "flatpak"
}

# A sandboxed app may not query a different app.
testcase_05_sandbox_query_target_denied() {
    local tpid
    tpid="$(start_bg_app com.example.T5Target)"

    call_as_app_expect_denied '{"id":"com.example.T5","sandbox":"flatpak"}' \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$tpid"'}}'

    kill "$tpid" 2>/dev/null || true
}

# A plainly registered app may set its own permissions, and they stick. Query/SetPermissions/Query share
# one run_as_app invocation so they run as a single app instance.
testcase_06_register_setperms_self() {
    local out
    out="$(run_as_app '{"id":"com.example.T6"}' bash -c '
        q="$(varlinkctl call --json=short "$1" io.systemd.AppInstance.Query "{}")"
        gen="$(jq -r .generation <<<"$q")"
        varlinkctl call "$1" io.systemd.AppInstance.SetPermissions \
            "{\"generation\":$gen,\"permissions\":{\"testperm\":true}}" >/dev/null
        varlinkctl call --json=short "$1" io.systemd.AppInstance.Query "{}"
    ' _ "$SOCK")"
    assert_eq "$(jq -r '.permissions.testperm' <<<"$out")" "true"
}

# A sandboxed app may not set its own permissions
testcase_07_sandbox_setperms_self_denied() {
    call_as_app_expect_denied '{"id":"com.example.T7","sandbox":"flatpak"}' \
        io.systemd.AppInstance.SetPermissions '{"generation":0,"permissions":{}}'
}

# A sandboxed app may not set another app's permissions.
testcase_08_sandbox_setperms_target_denied() {
    local tpid
    tpid="$(start_bg_app com.example.T8Target)"

    call_as_app_expect_denied '{"id":"com.example.T8","sandbox":"flatpak"}' \
        io.systemd.AppInstance.SetPermissions \
        '{"targetPid":{"pid":'"$tpid"'},"generation":0,"permissions":{}}'

    kill "$tpid" 2>/dev/null || true
}

# Registering twice before any query amends the registration
testcase_09_double_register_query() {
    local out
    # Note that run_as_app does the first registration!
    out="$(run_as_app '{"id":"com.example.T9"}' bash -c '
        varlinkctl call "$1" io.systemd.AppInstance.Register "$2" >/dev/null
        varlinkctl call --json=short "$1" io.systemd.AppInstance.Query "{}"
    ' _ "$SOCK" '{"id":"com.example.T9","collection":"org.flathub","sandbox":"flatpak"}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.T9"
    assert_eq "$(jq -r .collection <<<"$out")" "org.flathub"
    assert_eq "$(jq -r .sandbox <<<"$out")" "flatpak"
}

# Target an app by a connection FD
testcase_10_target_by_socket() {
    local appsock out
    appsock="$RUNTIME/appd-target.$RANDOM.sock"

    # Here we start a "service": It creates a socket, and when an app connects
    # to that socket the service queries the app's identity. Our service here
    # then sends appd's return value right back to the app
    rm -f "$appsock"
    systemctl_user reset-failed appd-socktarget.service 2>/dev/null || true
    systemd-run --user --machine "testuser@" --quiet --unit=appd-socktarget.service -p Type=notify -- \
        systemd-socket-activate --accept --inetd -l "$appsock" -- \
            varlinkctl call --json=short --push-fd=0 "$SOCK" io.systemd.AppInstance.Query '{"targetConnection":0}' >&2

    # And now we run the app, have it connect to the service, and make sure
    # we got the expected registration back!
    out="$(run_as_app '{"id":"com.example.SockTarget"}' socat -U - "UNIX-CONNECT:$appsock")"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.SockTarget"

    systemctl_user stop appd-socktarget.service 2>/dev/null || true
    rm -f "$appsock"
}

# Target an app by its cgroup path
testcase_11_target_by_cgroup() {
    local pid out1 cg out2
    pid="$(start_bg_app com.example.CgTarget)"

    out1="$(user_run_wait varlinkctl call --json=short "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    cg="$(jq -r .cgroup <<<"$out1")"
    assert_neq "$cg" ""

    out2="$(user_run_wait varlinkctl call --json=short "$SOCK" \
        io.systemd.AppInstance.Query '{"targetCgroup":"'"$cg"'"}')"
    assert_eq "$(jq -r .id <<<"$out2")" "com.example.CgTarget"

    kill "$pid" 2>/dev/null || true
}

run_testcases

touch /testok
