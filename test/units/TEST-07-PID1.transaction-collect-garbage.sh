#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test that transaction_collect_garbage() removes dependency cycles that are no longer anchored to any
# requested job.
#
# Scenario: units A and B form a dependency cycle (A Upholds=B, B BindsTo=A). When an unrelated unit U
# starts and pulls in an already-active intermediate target T (which Wants=A), the transaction should
# detect that the A↔B cycle is not reachable from the anchor (U) and garbage-collect it, preventing
# spurious re-execution of the cycle.

at_exit() {
    set +e

    systemctl stop test-gc-trigger.service test-gc-upheld.service test-gc-upholder.service test-gc-target.target 2>/dev/null
    systemctl reset-failed test-gc-trigger.service test-gc-upheld.service test-gc-upholder.service test-gc-target.target 2>/dev/null
    rm -f /run/systemd/system/test-gc-*.service /run/systemd/system/test-gc-*.target /tmp/test-gc-upholder.count
    systemctl daemon-reload
}

trap at_exit EXIT

mkdir -p /run/systemd/system

cat >/run/systemd/system/test-gc-target.target <<EOF
[Unit]
DefaultDependencies=no
Wants=test-gc-upholder.service
EOF

cat >/run/systemd/system/test-gc-upholder.service <<EOF
[Unit]
DefaultDependencies=no
Upholds=test-gc-upheld.service

[Service]
Type=oneshot
ExecCondition=/bin/sh -c 'echo x >> /tmp/test-gc-upholder.count; exit 1'
ExecStart=/bin/true
RemainAfterExit=yes
EOF

cat >/run/systemd/system/test-gc-upheld.service <<EOF
[Unit]
DefaultDependencies=no
BindsTo=test-gc-upholder.service
After=test-gc-upholder.service

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF

cat >/run/systemd/system/test-gc-trigger.service <<EOF
[Unit]
DefaultDependencies=no
Requires=test-gc-target.target
After=test-gc-target.target

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF

systemctl daemon-reload

rm -f /tmp/test-gc-upholder.count

# Start the target, which will try to start the upholder (A). A's ExecCondition fails, so A skips but B
# (upheld) still gets pulled in via Upholds= and fails due to the BindsTo= dependency.
systemctl start test-gc-target.target

# Wait for upholder to have been attempted (count file exists and is non-empty).
timeout 10 bash -c 'until [[ -s /tmp/test-gc-upholder.count ]]; do sleep 0.2; done'

# Clear failure state so the next transaction does not immediately skip the units.
systemctl reset-failed test-gc-upheld.service || true

before="$(wc -l < /tmp/test-gc-upholder.count)"

# Start the trigger. This pulls in the target (via Requires=), which is already active and thus redundant.
# The target's Wants=upholder would normally pull in the A↔B cycle again, but the garbage collector should
# detect that the cycle is not reachable from the anchor (trigger) and remove it before execution.
systemctl start test-gc-trigger.service

# Give the system some time to settle. If the cycle were not garbage-collected, upholder would be
# re-attempted and the count would increase.
sleep 2

assert_eq "$(wc -l < /tmp/test-gc-upholder.count)" "$before"

exit 0
