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

    # Verify that the user manager also preserved its FD store
    n_user_at_fds=$(systemctl show -P NFileDescriptorStore "${TESTUSER_USER_SVC}")
    test "${n_user_at_fds}" -ge 2
    write_late_unit user TEST-91-LIVEUPDATE-user-late \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check user-late"
    systemctl restart "${TESTUSER_USER_SVC}"
    timeout 30s bash -c "until systemctl is-active --quiet '${TESTUSER_USER_SVC}'; do sleep 0.5; done"
    n_user_unit_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore TEST-91-LIVEUPDATE-user-late.service)
    test "${n_user_unit_fds}" -eq 2
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
KillSignal=SIGKILL
EOF
    n_nspawn_fds=$(systemctl show -P NFileDescriptorStore systemd-nspawn@fdstore.service)
    test "${n_nspawn_fds}" -ge 2
    systemctl start systemd-nspawn@fdstore.service
    systemctl is-active systemd-nspawn@fdstore.service

    # late.service: rewrite the fragment with the second-boot ExecStart and
    # exercise the daemon-reload + daemon-reexec preservation paths.
    write_late_unit system TEST-91-LIVEUPDATE-late \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check"

    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    systemctl daemon-reload

    # Verify the late unit doesn't get GC'ed during daemon-reload
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    systemctl daemon-reexec

    # Verify the late unit doesn't get GC'ed during daemon-reexec
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    systemctl start TEST-91-LIVEUPDATE-late.service

    # No-reload variant: drop a brand-new fragment file but never call
    # daemon-reload. Lazy load via systemctl start must pick it up while
    # preserving the LUO-restored fds.
    write_late_unit system TEST-91-LIVEUPDATE-late-noreload \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo check late-noreload"
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late-noreload.service)
    test "$n_fds" -eq 2
    systemctl start TEST-91-LIVEUPDATE-late-noreload.service

    # Zero-fds variant: fragment on second boot sets FileDescriptorStoreMax=0,
    # so the LUO-restored fds must be dropped on (lazy) load.
    write_late_unit system TEST-91-LIVEUPDATE-late-zerofds \
        "bash -c 'test \"\${LISTEN_FDS:-0}\" -eq 0'" 0
    systemctl daemon-reload
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-91-LIVEUPDATE-late-zerofds.service)
    test "$n_fds" -eq 0
    systemctl start TEST-91-LIVEUPDATE-late-zerofds.service
else
    # Create memfds with known content and push them to our fd store.
    /usr/lib/systemd/tests/unit-tests/manual/test-luo store

    # Exercise the user manager FD preservation across kexec too
    loginctl enable-linger testuser
    timeout 30s bash -c "until systemctl is-active --quiet '${TESTUSER_USER_SVC}'; do sleep 0.5; done"
    write_late_unit user TEST-91-LIVEUPDATE-user-late \
        "/usr/lib/systemd/tests/unit-tests/manual/test-luo store user-late"
    run0 -u testuser systemctl --user start TEST-91-LIVEUPDATE-user-late.service
    n_user_unit_fds=$(run0 -u testuser systemctl --user show -P NFileDescriptorStore TEST-91-LIVEUPDATE-user-late.service)
    test "${n_user_unit_fds}" -eq 2
    n_user_at_fds=$(systemctl show -P NFileDescriptorStore "${TESTUSER_USER_SVC}")
    test "${n_user_at_fds}" -ge 2

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
KillSignal=SIGKILL
EOF

    systemctl start systemd-nspawn@fdstore.service
    timeout 30s bash -c \
        "until [[ \"\$(systemctl show -P NFileDescriptorStore systemd-nspawn@fdstore.service)\" -ge 2 ]]; do sleep 0.5; done"

    # Write and start each late unit with distinct session name prefixes
    # to avoid collisions in the LUO session namespace.
    for variant in late late-noreload late-zerofds; do
        write_late_unit system "TEST-91-LIVEUPDATE-${variant}" \
            "/usr/lib/systemd/tests/unit-tests/manual/test-luo store"
        systemctl start "TEST-91-LIVEUPDATE-${variant}.service"

        n_fds=$(systemctl show -P NFileDescriptorStore "TEST-91-LIVEUPDATE-${variant}.service")
        test "$n_fds" -eq 2
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
