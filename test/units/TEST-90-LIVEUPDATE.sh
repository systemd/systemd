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

# To test the late-load path also create a unit that appears at runtime
# ExecStart is added later depending on the test phase
cat >/run/systemd/system/TEST-90-LIVEUPDATE-late.service <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
FileDescriptorStoreMax=20
FileDescriptorStorePreserve=yes
EOF

if grep -qw luo_nboot=1 /proc/cmdline; then
    # Verify that the fd store of the main test service survived the kexec.
    /usr/lib/systemd/tests/unit-tests/manual/test-luo check

    # Complete and start the late unit
    cat >>/run/systemd/system/TEST-90-LIVEUPDATE-late.service <<EOF
ExecStart=/usr/lib/systemd/tests/unit-tests/manual/test-luo check
EOF

    # Verify the late unit has fds in its store
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-90-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    systemctl daemon-reload

    # Verify the late unit doesn't get GC'ed during daemon-reload
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-90-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    systemctl daemon-reexec

    # Verify the late unit doesn't get GC'ed during daemon-reexec
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-90-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    systemctl start TEST-90-LIVEUPDATE-late.service
else
    # Create memfds with known content and push them to our fd store.
    /usr/lib/systemd/tests/unit-tests/manual/test-luo store

    # Complete and start the late unit
    cat >>/run/systemd/system/TEST-90-LIVEUPDATE-late.service <<EOF
ExecStart=/usr/lib/systemd/tests/unit-tests/manual/test-luo store
EOF
    systemctl start TEST-90-LIVEUPDATE-late.service

    # Verify the late unit has fds in its store
    n_fds=$(systemctl show -P NFileDescriptorStore TEST-90-LIVEUPDATE-late.service)
    test "$n_fds" -eq 2

    # 'systemctl kexec' auto-loads the default boot entry (i.e. the booted UKI,
    # via EFI LoaderEntrySelected/LoaderEntryDefault). Append a marker to the
    # kernel command line so we can tell the two boots apart, and also the current
    # cmdline that is added by mkosi, otherwise the test framework will break.
    systemctl kexec --kernel-cmdline="$(cat /proc/cmdline) luo_nboot=1"
    exit 0
fi

touch /testok
systemctl --no-block exit 123
