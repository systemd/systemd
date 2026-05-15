#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test RestrictFileSystemAccess= configuration parsing and graceful failure modes.
#
# Runs in a VM WITHOUT dm_verity.require_signatures=1, so enabling RestrictFileSystemAccess
# triggers the require_signatures error path without activating enforcement.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# RestrictFileSystemAccess= requires +BPF_FRAMEWORK at compile time
if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
    echo "BPF framework not compiled in, skipping"
    exit 0
fi

HELPER=/usr/lib/systemd/tests/unit-tests/manual/test-bpf-restrict-fsaccess
CURSOR_FILE=/tmp/restrict-fsaccess-config.cursor

cleanup() {
    rm -f "$CURSOR_FILE"
    rm -f /run/systemd/system.conf.d/50-restrict-fsaccess.conf
}
trap cleanup EXIT

disable_restrict_fsaccess() {
    rm -f /run/systemd/system.conf.d/50-restrict-fsaccess.conf
}

# ------ Test case 1: Default (RestrictFileSystemAccess=no) — no log messages ------

testcase_default_no_messages() {
    disable_restrict_fsaccess

    # Save a journal cursor so we only check messages from after this point.
    journalctl -q -n 0 --cursor-file="$CURSOR_FILE"

    systemctl daemon-reexec
    # daemon-reexec is synchronous: PID1 has completed startup (including any
    # RestrictFileSystemAccess= setup) and is back on D-Bus by the time it returns. PID1
    # logs to kmsg synchronously, so messages are already in the journal.

    # No RestrictFileSystemAccess-related messages should appear
    if journalctl --cursor-file="$CURSOR_FILE" -o cat _PID=1 | grep "bpf-restrict-fsaccess" >/dev/null 2>&1; then
        echo "Unexpected RestrictFileSystemAccess log messages with RestrictFileSystemAccess=no"
        return 1
    fi
}

# ------ Test case 2: require_signatures check via helper binary ------
#
# The helper binary runs the same precondition checks as PID1 (BPF LSM
# availability, dm-verity require_signatures). When require_signatures is
# off the check must fail — this verifies the C code gate without going
# through daemon-reexec (which would kill PID1).

testcase_no_require_signatures_helper() {
    if ! kernel_supports_lsm bpf; then
        echo "BPF LSM not available, skipping require_signatures test"
        return 0
    fi

    # Check that the kernel has the bdev_setintegrity LSM hook in BTF.
    # Without it the skeleton fails to load and the check reports "BPF LSM
    # is not available" which masks the real reason.
    if command -v bpftool >/dev/null 2>&1; then
        if ! bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep 'bpf_lsm_bdev_setintegrity' >/dev/null; then
            echo "Kernel lacks bdev_setintegrity LSM hook, skipping require_signatures test"
            return 0
        fi
    fi

    if [[ ! -x "$HELPER" ]]; then
        echo "Helper binary not found, skipping"
        return 0
    fi

    # This VM boots WITHOUT require_signatures.
    if [[ -e /sys/module/dm_verity/parameters/require_signatures ]]; then
        local val
        val="$(cat /sys/module/dm_verity/parameters/require_signatures)"
        if [[ "$val" == "Y" || "$val" == "1" ]]; then
            echo "require_signatures already enabled, skipping (enforce VM covers this)"
            return 0
        fi
    fi

    # The helper's "check" command runs the same bpf_restrict_fsaccess_supported()
    # and dm_verity_require_signatures() checks that PID1 uses. It must fail
    # because require_signatures is not enabled.
    if "$HELPER" check; then
        echo "ERROR: helper check succeeded but require_signatures is not enabled"
        return 1
    fi
    echo "Helper correctly rejected setup: require_signatures not enabled"
}

run_testcases
