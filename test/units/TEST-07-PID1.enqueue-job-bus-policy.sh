#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# These methods must reach PID 1 for unprivileged clients, so that PID 1 can perform
# authorization. Invalid arguments let us distinguish its response from a bus policy
# denial without requiring polkit or actually enqueueing a job.
# https://github.com/systemd/systemd/issues/44289
for invalid in type mode; do
    job_type=start
    job_mode=replace
    if [[ "$invalid" == type ]]; then
        job_type="invalid-job-type"
    else
        job_mode="invalid-job-mode"
    fi

    for method in EnqueueUnitJob EnqueueUnitJobMany EnqueueJob; do
        path=/org/freedesktop/systemd1
        interface=org.freedesktop.systemd1.Manager
        case "$method" in
            EnqueueUnitJob)
                args=(sss basic.target "$job_type" "$job_mode")
                ;;
            EnqueueUnitJobMany)
                args=(assst 2 basic.target sysinit.target "$job_type" "$job_mode" 0)
                ;;
            EnqueueJob)
                path=/org/freedesktop/systemd1/unit/basic_2etarget
                interface=org.freedesktop.systemd1.Unit
                args=(ss "$job_type" "$job_mode")
                ;;
        esac

        output=$(runas testuser busctl --system call \
            org.freedesktop.systemd1 "$path" "$interface" "$method" "${args[@]}" 2>&1) && assert_not_reached
        assert_in "Job $invalid invalid-job-$invalid invalid" "$output"
    done
done
