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
for method in EnqueueUnitJob EnqueueUnitJobMany; do
    if [[ "$method" == EnqueueUnitJob ]]; then
        args=(sss basic.target invalid-job-type replace)
    else
        args=(assst 1 basic.target invalid-job-type replace 0)
    fi

    output=$(runas testuser busctl --system call \
        org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager "$method" "${args[@]}" 2>&1) && assert_not_reached
    assert_in 'Job type invalid-job-type invalid' "$output"
done

output=$(runas testuser busctl --system call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/basic_2etarget \
    org.freedesktop.systemd1.Unit EnqueueJob ss invalid-job-type replace 2>&1) && assert_not_reached
assert_in 'Job type invalid-job-type invalid' "$output"
