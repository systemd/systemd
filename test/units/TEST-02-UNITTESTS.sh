#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! systemd-detect-virt -qc && [[ "${TEST_CMDLINE_NEWLINE:-}" != bar ]]; then
    cat /proc/cmdline
    echo >&2 "Expected TEST_CMDLINE_NEWLINE=bar from the kernel command line"
    exit 1
fi

if [[ -z "${TEST_MATCH_SUBTEST:-}" ]]; then
    # If we're running with TEST_PREFER_NSPAWN=1 limit the set of tests we run
    # in QEMU to only those that can't run in a container to avoid running
    # the same tests again in a, most likely, very slow environment
    if ! systemd-detect-virt -qc && [[ "${TEST_PREFER_NSPAWN:-0}" -ne 0 ]]; then
        TEST_MATCH_SUBTEST="test-loop-block"
    else
        TEST_MATCH_SUBTEST="test-*"
    fi
fi

NPROC=$(nproc)
MAX_QUEUE_SIZE=${NPROC:-2}

# Reset state
rm -fv /failed /skipped /testok
touch /lock

if ! systemd-detect-virt -qc; then
    # Make sure ping works for unprivileged users (for test-bpf-firewall)
    sysctl net.ipv4.ping_group_range="0 2147483647"
fi

# Check & report test results
# Arguments:
#   $1: test path
#   $2: test exit code
run_test() {
    if [[ $# -ne 1 ]]; then
        echo >&2 "run_test: missing arguments"
        exit 1
    fi

    local test="$1"
    local name="${test##*/}"
    local environment=

    echo "Executing test $name as unit $name.service"

    case "$name" in
        test-journal-flush)
            environment="SYSTEMD_LOG_LEVEL=info"
            ;;
        test-journal-verify)
            environment="SYSTEMD_LOG_LEVEL=crit"
            ;;
    esac

    systemd-run \
        --quiet \
        --property Delegate=1 \
        --property EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
        --property "Environment=$environment" \
        --unit="$name" \
        --wait "$test" && ret=0 || ret=$?

    exec {LOCK_FD}> /lock
    flock --exclusive ${LOCK_FD}

    if [[ $ret -eq 77 ]] || [[ $ret -eq 127 ]]; then
        echo "$name skipped"
        echo "$name" >>/skipped-tests
        {
            echo "--- $name begin ---"
            journalctl --unit="$name" --no-hostname -o short-monotonic
            echo "--- $name end ---"
        } >>/skipped
    elif [[ $ret -ne 0 ]]; then
        echo "$name failed with $ret"
        echo "$name" >>/failed-tests
        {
            echo "--- $name begin ---"
            journalctl --unit="$name" --no-hostname -o short-monotonic
            echo "--- $name end ---"
        } >>/failed
    else
        echo "$name OK"
        echo "$name" >>/testok
    fi

    exec {LOCK_FD}<&-
}

export -f run_test

find /usr/lib/systemd/tests/unit-tests/ -maxdepth 1 -type f -name "${TEST_MATCH_SUBTEST}" -print0 |
    xargs -0 -I {} --max-procs="$MAX_QUEUE_SIZE" bash -ec "run_test {}"

# Write all pending messages, so they don't get mixed with the summaries below
journalctl --sync

# No need for full test logs in this case
if [[ -s /skipped-tests ]]; then
    : "=== SKIPPED TESTS ==="
    cat /skipped-tests
fi

if [[ -s /failed ]]; then
    : "=== FAILED TESTS ==="
    cat /failed
fi

# Test logs are sometimes lost, as the system shuts down immediately after
journalctl --sync

test ! -s /failed
touch /testok
