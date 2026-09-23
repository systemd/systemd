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
MONDIR="$RUNTIME/systemd/io.systemd.AppInstanceMonitor"

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
    systemctl_user stop appd-monitor.service 2>/dev/null
    systemctl_user stop systemd-appd.service 2>/dev/null
    loginctl disable-linger testuser 2>/dev/null
}

trap at_exit EXIT

loginctl enable-linger testuser
systemctl start "user@$TESTUSER_UID.service"

systemctl_user reset-failed systemd-appd.service 2>/dev/null || true
systemctl_user start systemd-appd.service

# Turn on debug logging in appd
systemctl_user kill --kill-value=0x107 -s RTMIN+18 systemd-appd.service

# A plain unit whose name follows the app scheme is discovered by appd, and can be queried by PID.
testcase_systemd_run_query_by_pid() {
    local pid out
    pid="$(start_bg_app com.example.QBP)"

    out="$(user_run_wait varlinkctl call "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.QBP"

    kill "$pid" 2>/dev/null || true
}

# Registering moves the caller into a fresh app scope, and we can query the app
testcase_register_and_query_by_pid() {
    local pid out units pidfile
    pidfile="$RUNTIME/appd-pid-rqbp.$RANDOM"

    rm -f "$pidfile"
    # systemd-run collapses "$$" to "$", so we need "$$$$"
    systemd-run --user --machine "testuser@" --quiet -p Type=exec -- \
        varlinkctl --exec call "$SOCK" io.systemd.AppInstance.Register '{"id":"com.example.RQBP"}' -- \
            bash -c "echo \$\$\$\$ >'$pidfile'; exec sleep infinity" >&2
    timeout 60 bash -c "until [[ -s '$pidfile' ]]; do sleep 0.2; done"
    pid="$(cat "$pidfile")"

    out="$(user_run_wait varlinkctl call "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.RQBP"

    units="$(systemctl_user list-units --all --no-legend --plain || true)"
    grep -E 'app-com\.example\.RQBP-[0-9]+\.scope' <<<"$units" >/dev/null

    kill "$pid" 2>/dev/null || true
}

# A plainly registered app can query itself and gets its own data back (no sandbox set).
testcase_register_query_self() {
    local out
    out="$(run_as_app '{"id":"com.example.QS"}' \
        varlinkctl call "$SOCK" io.systemd.AppInstance.Query '{}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.QS"
    assert_eq "$(jq -r '.sandbox // "none"' <<<"$out")" "none"
}

# A sandboxed app is still allowed to query itself.
testcase_register_sandbox_query_self() {
    local out
    out="$(run_as_app '{"id":"com.example.RSQS","sandbox":"flatpak"}' \
        varlinkctl call "$SOCK" io.systemd.AppInstance.Query '{}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.RSQS"
    assert_eq "$(jq -r .sandbox <<<"$out")" "flatpak"
}

# A sandboxed app may not query a different app.
testcase_sandbox_query_target_denied() {
    local tpid
    tpid="$(start_bg_app com.example.SQTDTarget)"

    call_as_app_expect_denied '{"id":"com.example.SQTD","sandbox":"flatpak"}' \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$tpid"'}}'

    kill "$tpid" 2>/dev/null || true
}

# Invalid IDs should be rejected
assert_app_id_invalid() {
    local out
    out="$(user_run_wait varlinkctl call "$SOCK" \
        --graceful=org.varlink.service.InvalidParameter \
        io.systemd.AppInstance.Register '{"id":"'"$1"'"}' 2>&1)"
    grep "returned expected error: org.varlink.service.InvalidParameter" <<<"$out" >/dev/null
}
testcase_invalid_appid() {
    assert_app_id_invalid ""
    assert_app_id_invalid "org.example.Bad\x2dname"
    assert_app_id_invalid "org.example.Foo@bar"
    assert_app_id_invalid "org.example.€"
    assert_app_id_invalid "org.example/Something"
    assert_app_id_invalid "My Awesome App"
}

# An unsandboxed app may set its own permissions
testcase_register_setperms_self() {
    local out
    # shellcheck disable=SC2016
    out="$(run_as_app '{"id":"com.example.RSPS"}' bash -c '
        q="$(varlinkctl call "$1" io.systemd.AppInstance.Query "{}")"
        gen="$(jq -r .generation <<<"$q")"
        varlinkctl call "$1" io.systemd.AppInstance.SetPermissions \
            "{\"generation\":$gen,\"permissions\":{\"testperm\":true}}" >/dev/null
        varlinkctl call "$1" io.systemd.AppInstance.Query "{}"
    ' _ "$SOCK")"
    assert_eq "$(jq -r '.permissions.testperm' <<<"$out")" "true"
}

# A sandboxed app may not set its own permissions
testcase_sandbox_setperms_self_denied() {
    call_as_app_expect_denied '{"id":"com.example.SSPSD","sandbox":"flatpak"}' \
        io.systemd.AppInstance.SetPermissions '{"generation":0,"permissions":{}}'
}

# A sandboxed app may not set another app's permissions.
testcase_sandbox_setperms_target_denied() {
    local tpid
    tpid="$(start_bg_app com.example.SSPTDTarget)"

    call_as_app_expect_denied '{"id":"com.example.SSPTD","sandbox":"flatpak"}' \
        io.systemd.AppInstance.SetPermissions \
        '{"targetPid":{"pid":'"$tpid"'},"generation":0,"permissions":{}}'

    kill "$tpid" 2>/dev/null || true
}

# Expect error on stale set permissions
testcase_setperms_stale() {
    local out
    # shellcheck disable=SC2016
    out="$(run_as_app '{"id":"com.example.RSPS"}' bash -c '
        q="$(varlinkctl call "$1" io.systemd.AppInstance.Query "{}")"
        gen="$(jq -r .generation <<<"$q")"
        gen="$(( gen - 1 ))"
        varlinkctl call "$1" io.systemd.AppInstance.SetPermissions \
            --graceful=io.systemd.AppInstance.Stale \
            "{\"generation\":$gen,\"permissions\":{\"testperm\":true}}" 2>&1
    ' _ "$SOCK")"
    grep "returned expected error: io.systemd.AppInstance.Stale" <<<"$out" >/dev/null
}

# Registering twice before any query amends the registration
testcase_double_register_query() {
    local out
    # Note that run_as_app does the first registration!
    # shellcheck disable=SC2016
    out="$(run_as_app '{"id":"com.example.DRQ"}' bash -c '
        varlinkctl call "$1" io.systemd.AppInstance.Register "$2" >/dev/null
        varlinkctl call "$1" io.systemd.AppInstance.Query "{}"
    ' _ "$SOCK" '{"id":"com.example.DRQ","collection":"org.flathub","sandbox":"flatpak"}')"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.DRQ"
    assert_eq "$(jq -r .collection <<<"$out")" "org.flathub"
    assert_eq "$(jq -r .sandbox <<<"$out")" "flatpak"
}

# Querying should prevent further registrations
testcase_query_then_double_register_busy() {
    local out
    # shellcheck disable=SC2016
    out="$(run_as_app '{"id":"com.example.QDRB"}' bash -c '
        varlinkctl call "$1" io.systemd.AppInstance.Query "{}" >/dev/null
        varlinkctl call --graceful=io.systemd.AppInstance.RegistrationBusy \
           "$1" io.systemd.AppInstance.Register "$2" 2>&1
    ' _ "$SOCK" '{"id":"com.example.QDRB","collection":"org.flathub"}')"
    grep "returned expected error: io.systemd.AppInstance.RegistrationBusy" <<<"$out" >/dev/null
}

# Target an app by a connection FD
testcase_target_by_socket() {
    local appsock out
    appsock="$RUNTIME/appd-target.$RANDOM.sock"

    # Here we start a "service": It creates a socket, and when an app connects
    # to that socket the service queries the app's identity. Our service here
    # then sends appd's return value right back to the app
    rm -f "$appsock"
    systemctl_user reset-failed appd-socktarget.service 2>/dev/null || true
    systemd-run --user --machine "testuser@" --quiet --unit=appd-socktarget.service -p Type=notify -- \
        systemd-socket-activate --accept --inetd -l "$appsock" -- \
            varlinkctl call --push-fd=0 "$SOCK" io.systemd.AppInstance.Query '{"targetConnection":0}' >&2

    # And now we run the app, have it connect to the service, and make sure
    # we got the expected registration back!
    out="$(run_as_app '{"id":"com.example.SockTarget"}' socat -U - "UNIX-CONNECT:$appsock")"
    assert_eq "$(jq -r .id <<<"$out")" "com.example.SockTarget"

    systemctl_user stop appd-socktarget.service 2>/dev/null || true
    rm -f "$appsock"
}

# Target an app by its unique ID (cgroup path)
testcase_target_by_unique_id() {
    local pid out1 cg out2
    pid="$(start_bg_app com.example.CgTarget)"

    out1="$(user_run_wait varlinkctl call "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    cg="$(jq -r .uniqueId <<<"$out1")"
    assert_neq "$cg" ""

    out2="$(user_run_wait varlinkctl call "$SOCK" \
        io.systemd.AppInstance.Query '{"targetUniqueId":"'"$cg"'"}')"
    assert_eq "$(jq -r .id <<<"$out2")" "com.example.CgTarget"

    kill "$pid" 2>/dev/null || true
}

# Bogus cgroup target
testcase_target_by_unique_id_invalid() {
    local out cg
    cg="/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.example.BogusCgroup.service"
    out="$(user_run_wait varlinkctl call "$SOCK" \
        --graceful=io.systemd.AppInstance.NoSuchInstance \
        io.systemd.AppInstance.Query '{"targetUniqueId":"'"$cg"'"}' 2>&1)"
    grep "returned expected error: io.systemd.AppInstance.NoSuchInstance" <<<"$out" >/dev/null
}

# Conflicting targets
testcase_target_conflicting() {
    local pid out1 cg out2
    pid1="$(start_bg_app com.example.ConflictingTarget1)"
    pid2="$(start_bg_app com.example.ConflictingTarget2)"

    out1="$(user_run_wait varlinkctl call "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid1"'}}')"
    cg="$(jq -r .uniqueId <<<"$out1")"
    assert_neq "$cg" ""

    out2="$(user_run_wait varlinkctl call "$SOCK" \
        --graceful=io.systemd.AppInstance.ConflictingTarget \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid2"'},"targetUniqueId":"'"$cg"'"}' 2>&1)"
    grep "returned expected error: io.systemd.AppInstance.ConflictingTarget" <<<"$out2" >/dev/null

    kill "$pid1" 2>/dev/null || true
    kill "$pid2" 2>/dev/null || true
}

# No instance
testcase_no_such_instance() {
    local out
    out="$(user_run_wait varlinkctl call "$SOCK" \
        --graceful=io.systemd.AppInstance.NoSuchInstance \
        io.systemd.AppInstance.Query '{}' 2>&1)"
    grep "returned expected error: io.systemd.AppInstance.NoSuchInstance" <<<"$out" >/dev/null
}

# Notifications on changes / app disappearing
testcase_notification_sockets() {
    local log monsock pid out gen
    log="$RUNTIME/appd-monitor.log.$RANDOM"
    monsock="$MONDIR/responder.sock"

    # Impl of io.systemd.AppInstanceMonitor that logs the notifs to a file
    rm -f "$log"
    systemctl_user reset-failed appd-monitor.service 2>/dev/null || true
    # shellcheck disable=SC2016
    systemd-run --user --machine "testuser@" --quiet --unit=appd-monitor.service \
        -p Type=notify -p RuntimeDirectory="${MONDIR#"$RUNTIME"/}" -- \
            systemd-socket-activate --accept --inetd -l "$monsock" -- \
                bash -c 'IFS= read -r -d "" req
                    jq -r ".parameters | \"\(.event) \(.id) \(.uniqueId)\"" <<<"$req" >>"$0"
                    printf "{}\0"' "$log" >&2

    pid="$(start_bg_app com.example.NotifyTarget)"

    # Fire a changed notification (by changing permissions)
    out="$(user_run_wait varlinkctl call "$SOCK" \
        io.systemd.AppInstance.Query '{"targetPid":{"pid":'"$pid"'}}')"
    gen="$(jq -r .generation <<<"$out")"
    user_run_wait varlinkctl call "$SOCK" io.systemd.AppInstance.SetPermissions \
        '{"targetPid":{"pid":'"$pid"'},"generation":'"$gen"',"permissions":{"testperm":true}}'
    # This is synchronous, so the log line should be there by the time SetPermissions returns
    grep -E 'changed com\.example\.NotifyTarget ' "$log" >/dev/null

    # Make the app quit so that we get notified of its disappearance (asynchronously)
    kill "$pid" 2>/dev/null || true
    timeout 30 bash -c "until grep -E 'disappeared com\.example\.NotifyTarget ' '$log' >/dev/null 2>&1; do sleep 0.2; done"

    systemctl_user stop appd-monitor.service 2>/dev/null || true
    rm -f "$log"
}

run_testcases

touch /testok
