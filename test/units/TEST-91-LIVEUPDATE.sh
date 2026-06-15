#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

# This test verifies that the Live Update Orchestrator (LUO) integration works:
# - PID 1 can serialize fd stores and pass them to systemd-shutdown
# - systemd-shutdown can preserve fds in a LUO session before kexec
# - After kexec, PID 1 restores the fd stores from the LUO session
#
# The test requires KHO (Kexec HandOver) and LUO (Live Update Orchestrator) kernel support.

if [[ ! -e /dev/liveupdate ]]; then
    echo "/dev/liveupdate not available, skipping test"
    exit 77
fi

# Ensure user units can also manage sessions
chmod 666 /dev/liveupdate

TESTUSER_UID=$(id -u testuser)
TESTUSER_USER_SVC="user@${TESTUSER_UID}.service"

at_exit() {
    systemctl stop systemd-nspawn@fdstore.service ||:
    machinectl terminate fdstore ||:
    rm -rf /var/lib/machines/fdstore ||:
    rm -f /run/systemd/nspawn/fdstore.nspawn
}

trap at_exit EXIT

# To test the late-load path also create units that appear at runtime.
# Three variants exercise different fragment scenarios on second boot:
#  - late.service:          fragment present before fds are observed (daemon-reload triggered)
#  - late-noreload.service: fragment dropped only after kexec, never daemon-reloaded explicitly
#                           to exercise lazy load via systemctl start
#  - late-zerofds.service:  fragment on second boot sets FileDescriptorStoreMax=0,
#                           the previously stored fds must be dropped
write_late_unit() {
    local scope="${1:?}" name="${2:?}" cmd="${3:?}" maxfd="${4:-20}"
    local dir

    case "${scope}" in
        system) dir=/run/systemd/system ;;
        user)   dir=/run/systemd/user ;;
        *)      echo "unknown scope: ${scope}" >&2; return 1 ;;
    esac

    mkdir -p "${dir}"
    cat >"${dir}/${name}.service" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
FileDescriptorStoreMax=${maxfd}
FileDescriptorStorePreserve=yes
ExecStart=${cmd}
EOF
}

if grep -qw luo_nboot=1 /proc/cmdline; then
    # Verify that the fd store of the main test service survived the kexec.
    /usr/lib/systemd/tests/unit-tests/manual/test-luo check

    assert_eq "$(busctl -j get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager KexecsCount | jq -r '.data')" "1"

    # Negative path: a unit stored a child LUO session named like PID 1's own
    # ("systemd") on the first boot. PID 1's serialize step must have refused to
    # serialize that fd store entry (anti-hijack guard in
    # manager_luo_serialize_fd_stores()), so it must NOT have been restored: the
    # unit's fd store must be empty here.
    n_hijack_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-hijack.service)
    assert_eq "${n_hijack_fds}" "0"
    # Rewrite the unit with a second-boot ExecStart and start it, so check-hijack
    # runs inside the unit and inspects its own restored LISTEN_FDS, failing if
    # the hijack fd came back. Mirrors the late.service variants below.
    write_late_unit system TEST-91-LIVEUPDATE-hijack \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check-hijack"
    systemctl start TEST-91-LIVEUPDATE-hijack.service
    rm -f /run/systemd/system/TEST-91-LIVEUPDATE-hijack.service
    systemctl daemon-reload

    # Verify that the user manager also preserved its FD store
    n_user_at_fds=$(systemctl show -P NFileDescriptorStore "${TESTUSER_USER_SVC}")
    test "${n_user_at_fds}" -ge 3
    write_late_unit user TEST-91-LIVEUPDATE-user-late \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check user-late"
    systemctl restart "${TESTUSER_USER_SVC}"
    timeout 30s bash -c "until systemctl is-active --quiet '${TESTUSER_USER_SVC}'; do sleep 0.5; done"
    n_user_unit_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore TEST-91-LIVEUPDATE-user-late.service)
    test "${n_user_unit_fds}" -eq 3
    run0 -u testuser systemctl --user start TEST-91-LIVEUPDATE-user-late.service

    # nspawn fdstore variant: after kexec, PID 1 propagated the
    # systemd-nspawn@fdstore.service fdstore through LUO. Starting the service
    # then forwards the preserved fds via LISTEN_FDS to a fresh nspawn payload,
    # which verifies the content is intact.
    create_dummy_container /var/lib/machines/fdstore
    cat >/var/lib/machines/fdstore/sbin/init <<'EOF'
#!/usr/bin/env bash
set -e
exec /usr/bin/test-fdstore check
EOF
    chmod +x /var/lib/machines/fdstore/sbin/init
    mkdir -p /run/systemd/nspawn
    cat >/run/systemd/nspawn/fdstore.nspawn <<EOF
[Exec]
KillSignal=SIGTERM
EOF
    n_nspawn_fds=$(systemctl show -P NFileDescriptorStore systemd-nspawn@fdstore.service)
    test "${n_nspawn_fds}" -ge 2
    systemctl start systemd-nspawn@fdstore.service
    systemctl is-active systemd-nspawn@fdstore.service

    # late.service: rewrite the fragment with the second-boot ExecStart and
    # exercise the daemon-reload + daemon-reexec preservation paths.
    write_late_unit system TEST-91-LIVEUPDATE-late \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check late"

    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late.service)
    test "$n_fds" -eq 3

    systemctl daemon-reload

    # Verify the late unit doesn't get GC'ed during daemon-reload
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late.service)
    test "$n_fds" -eq 3

    systemctl daemon-reexec

    # Verify the late unit doesn't get GC'ed during daemon-reexec
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late.service)
    test "$n_fds" -eq 3

    systemctl start TEST-91-LIVEUPDATE-late.service

    # No-reload variant: drop a brand-new fragment file but never call
    # daemon-reload. Lazy load via systemctl start must pick it up while
    # preserving the LUO-restored fds.
    write_late_unit system TEST-91-LIVEUPDATE-late-noreload \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check late-noreload"
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late-noreload.service)
    test "$n_fds" -eq 3
    systemctl start TEST-91-LIVEUPDATE-late-noreload.service

    # Zero-fds variant: fragment on second boot sets FileDescriptorStoreMax=0,
    # so the LUO-restored fds must be dropped on (lazy) load.
    write_late_unit system TEST-91-LIVEUPDATE-late-zerofds \
        "bash -c 'test \"\${LISTEN_FDS:-0}\" -eq 0'" 0
    systemctl daemon-reload
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late-zerofds.service)
    test "$n_fds" -eq 0
    systemctl start TEST-91-LIVEUPDATE-late-zerofds.service

    # Verify that with FileDescriptorStorePreserve=on-success the fdstore is
    # discarded once the unit enters the permanent failed state, while still
    # being preserved across the transitionary failed states that precede
    # each automated auto-restart attempt. Use Restart=on-failure with
    # StartLimitBurst=2 so the manager runs the helper twice before
    # giving up. The helper:
    #   - on the first attempt pushes an fd into the fdstore, becomes ready,
    #     and then crashes,
    #   - on subsequent attempts asserts that the previously stored fd is
    #     handed back via $LISTEN_FDS (proving the fdstore survived the
    #     auto-restart) and then crashes again.
    # When the start-limit is hit the unit lands in the permanent failed
    # state, at which point the fdstore must be empty.
    cat >/run/TEST-91-LIVEUPDATE-failure.sh <<'EOF'
#!/usr/bin/env bash
set -eux
state_file=/run/TEST-91-LIVEUPDATE-failure.attempt
attempt=$(cat "$state_file" 2>/dev/null || echo 0)
attempt=$((attempt + 1))
echo "$attempt" > "$state_file"
if [[ "$attempt" -eq 1 ]]; then
    systemd-notify --fd=0 --fdname=mem </dev/zero
else
    # On any restart attempt the fdstore must have been preserved across the
    # transitionary failed state and handed back to us via $LISTEN_FDS. Drop a
    # marker file when the invariant is broken so the outer test can detect it.
    if [[ "${LISTEN_FDS:-0}" -lt 1 ]]; then
        touch /run/TEST-91-LIVEUPDATE-failure.preserve-broken
    fi
fi
systemd-notify --ready
# Give PID 1 a chance to process the FDSTORE=1/READY=1 notifications before
# we exit, so the fdstore add is observed by the manager.
sleep 0.5
exit 1
EOF
    chmod +x /run/TEST-91-LIVEUPDATE-failure.sh
    rm -f /run/TEST-91-LIVEUPDATE-failure.attempt \
          /run/TEST-91-LIVEUPDATE-failure.preserve-broken
    cat >/run/systemd/system/TEST-91-LIVEUPDATE-failure.service <<EOF
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=2
[Service]
Type=notify
NotifyAccess=all
FileDescriptorStoreMax=4
FileDescriptorStorePreserve=on-success
Restart=on-failure
RestartSec=100ms
ExecStart=/run/TEST-91-LIVEUPDATE-failure.sh
EOF
    systemctl daemon-reload
    systemctl start TEST-91-LIVEUPDATE-failure.service || true
    timeout 60s bash -c \
        "until [[ \"\$(systemctl show -P ActiveState TEST-91-LIVEUPDATE-failure.service)\" == failed ]]; do sleep 0.5; done"
    # Sanity: the helper ran more than once, proving the fdstore was preserved
    # across at least one auto-restart attempt.
    test "$(cat /run/TEST-91-LIVEUPDATE-failure.attempt)" -ge 2
    # And the in-flight preservation invariant must hold for every restart.
    test ! -e /run/TEST-91-LIVEUPDATE-failure.preserve-broken
    # And the fdstore must be empty now that the permanent failed state was
    # reached, since FileDescriptorStorePreserve=on-success is set.
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-failure.service)
    test "$n_fds" -eq 0
    systemctl reset-failed TEST-91-LIVEUPDATE-failure.service
    rm -f /run/systemd/system/TEST-91-LIVEUPDATE-failure.service \
          /run/TEST-91-LIVEUPDATE-failure.sh \
          /run/TEST-91-LIVEUPDATE-failure.attempt \
          /run/TEST-91-LIVEUPDATE-failure.preserve-broken
    systemctl daemon-reload
else
    # Create memfds with known content and push them to our fd store.
    # Also request a LUO session, store a memfd in it, and push the session fd to the fd store.
    /usr/lib/systemd/tests/unit-tests/manual/test-luo store

    # Exercise the user manager FD preservation across kexec too
    loginctl enable-linger testuser
    timeout 30s bash -c "until systemctl is-active --quiet '${TESTUSER_USER_SVC}'; do sleep 0.5; done"
    write_late_unit user TEST-91-LIVEUPDATE-user-late \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo store user-late"
    run0 -u testuser systemctl --user start TEST-91-LIVEUPDATE-user-late.service
    n_user_unit_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore TEST-91-LIVEUPDATE-user-late.service)
    test "${n_user_unit_fds}" -eq 3
    n_user_at_fds=$(systemctl show -P NFileDescriptorStore "${TESTUSER_USER_SVC}")
    test "${n_user_at_fds}" -ge 3

    # Exercise the FD-store preservation chain across a kexec for a privileged
    # nspawn container managed as a system service:
    #   payload (inside container) -> systemd-nspawn@fdstore.service fdstore
    #   -> LUO -> after kexec PID 1 restores the fdstore -> systemd-nspawn ->
    #   payload verifies content matches.
    create_dummy_container /var/lib/machines/fdstore
    cat >/var/lib/machines/fdstore/sbin/init <<'EOF'
#!/usr/bin/env bash
set -e
exec /usr/bin/test-fdstore store
EOF
    chmod +x /var/lib/machines/fdstore/sbin/init

    mkdir -p /run/systemd/nspawn
    cat >/run/systemd/nspawn/fdstore.nspawn <<EOF
[Exec]
KillSignal=SIGTERM
EOF

    systemctl start systemd-nspawn@fdstore.service
    timeout 30s bash -c \
        "until [[ \"\$(systemctl show -P NFileDescriptorStore systemd-nspawn@fdstore.service)\" -ge 2 ]]; do sleep 0.5; done"

    # Negative path: store a fd store entry that holds a child LUO session named
    # like PID 1's own ("systemd"). On kexec PID 1 must refuse to serialize it
    # (anti-hijack guard), so it must not be restored on the next boot.
    write_late_unit system TEST-91-LIVEUPDATE-hijack \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo store-hijack"
    systemctl start TEST-91-LIVEUPDATE-hijack.service
    timeout 30s bash -c \
        "until [[ \"\$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-hijack.service)\" -ge 1 ]]; do sleep 0.5; done"

    # Write and start each late unit with distinct session name prefixes
    # to avoid collisions in the LUO session namespace.
    for variant in late late-noreload late-zerofds; do
        write_late_unit system "TEST-91-LIVEUPDATE-${variant}" \
            "/usr/lib/systemd/tests/unit-tests/manual/test-luo store ${variant}"
        systemctl start "TEST-91-LIVEUPDATE-${variant}.service"

        n_fds=$(systemctl show -P NFileDescriptorStore "TEST-91-LIVEUPDATE-${variant}.service")
        test "$n_fds" -eq 3
    done

    # 'systemctl kexec' auto-loads the default boot entry (i.e. the booted UKI,
    # via EFI LoaderEntrySelected/LoaderEntryDefault). Append a marker to the
    # kernel command line so we can tell the two boots apart, and also the current
    # cmdline that is added by mkosi, otherwise the test framework will break.
    systemctl kexec --kernel-cmdline="$(cat /proc/cmdline) luo_nboot=1"
    exit 0
fi

touch /testok
systemctl --no-block exit 123
