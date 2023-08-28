#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemd-analyze log-level debug
export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_PAGER=cat

if ! grep -q pidfd_open /proc/kallsyms; then
    echo "pidfds not available" >/skipped
    exit 0
fi

systemd-run --unit test-aux-scope.service \
            -p Slice=aux.slice -p Type=exec -p TasksMax=99 -p CPUWeight=199 -p IPAccounting=yes \
            /usr/lib/systemd/tests/unit-tests/manual/test-aux-scope
kill -s USR1 "$(systemctl show --value --property MainPID test-aux-scope.service)"

sleep 1

systemctl status test-aux-scope.service
systemctl status test-aux-scope.scope

test "$(systemctl show -p Slice --value test-aux-scope.scope) = aux.slice"
test "$(systemctl show -p TasksMax --value test-aux-scope.scope) = 99"
test "$(systemctl show -p CPUWeight --value test-aux-scope.scope) = 199"
test "$(systemctl show -p IPAccounting --value test-aux-scope.scope) = yes"

systemd-analyze log-level info
touch /testok
