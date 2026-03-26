#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test RestrictExec= configuration parsing and graceful failure modes.
#
# Runs in a VM WITHOUT dm_verity.require_signatures=1, so enabling RestrictExec
# triggers the require_signatures error path without activating enforcement.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# RestrictExec= requires +BPF_FRAMEWORK at compile time
if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
    echo "BPF framework not compiled in, skipping"
    exit 0
fi

HELPER=/usr/lib/systemd/tests/unit-tests/manual/test-bpf-restrict-exec

enable_restrict_exec() {
    mkdir -p /run/systemd/system.conf.d
    cat >/run/systemd/system.conf.d/50-restrict-exec.conf <<EOF
[Manager]
RestrictExec=yes
EOF
}

disable_restrict_exec() {
    rm -f /run/systemd/system.conf.d/50-restrict-exec.conf
}

# Clear the kernel ring buffer so we can check for messages after daemon-reexec
# without matching stale entries from previous testcases.
clear_kmsg() {
    dmesg --clear
}

# Wait for a dmesg pattern to appear (up to 10s). Use this instead of a fixed
# sleep after daemon-reexec to avoid flaky timing-dependent failures.
wait_for_dmesg() {
    local pattern="$1"
    local i
    for ((i = 0; i < 10; i++)); do
        if dmesg | grep "$pattern" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for dmesg pattern: $pattern" >&2
    return 1
}

# ------ Test case 1: Default (RestrictExec=no) — no log messages ------

testcase_default_no_messages() {
    disable_restrict_exec
    clear_kmsg

    systemctl daemon-reexec
    # daemon-reexec is synchronous: PID1 has completed startup (including any
    # RestrictExec= setup) and is back on D-Bus by the time it returns. PID1
    # logs to kmsg synchronously, so messages are already visible.

    # No RestrictExec-related messages should appear
    if dmesg | grep "bpf-restrict-exec" >/dev/null 2>&1; then
        echo "Unexpected RestrictExec log messages with RestrictExec=no"
        return 1
    fi
}

# ------ Test case 2: RestrictExec=yes without BPF LSM — warning ------

testcase_no_bpf_lsm() {
    if kernel_supports_lsm bpf; then
        echo "BPF LSM is available, skipping no-LSM test"
        return 0
    fi

    enable_restrict_exec
    clear_kmsg

    systemctl daemon-reexec
    wait_for_dmesg "BPF LSM is not available"

    disable_restrict_exec
    systemctl daemon-reexec
}

# ------ Test case 3: require_signatures check via helper binary ------
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

    # The helper's "check" command runs the same bpf_restrict_exec_supported()
    # and dm_verity_require_signatures() checks that PID1 uses. It must fail
    # because require_signatures is not enabled.
    if "$HELPER" check; then
        echo "ERROR: helper check succeeded but require_signatures is not enabled"
        return 1
    fi
    echo "Helper correctly rejected setup: require_signatures not enabled"
}

run_testcases
