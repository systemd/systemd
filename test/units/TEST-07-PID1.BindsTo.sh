#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test BindsTo= dependency propagation when the dependency is skipped by a condition.
# When a BindsTo= dependency is skipped by a condition (ConditionXYZ= or ExecCondition=),
# the job for the dependent unit should be cancelled (failure propagation).

at_exit() {
    set +e

    systemctl stop test-bindsto-bound.service test-bindsto-spacer.service test-bindsto-skip.service
    systemctl stop test-bindsto-upheld.service test-bindsto-upholder.service
    systemctl reset-failed test-bindsto-bound.service test-bindsto-spacer.service test-bindsto-skip.service
    systemctl reset-failed test-bindsto-upheld.service test-bindsto-upholder.service
    rm -f /run/systemd/system/test-bindsto-*.service
    systemctl daemon-reload
}

trap at_exit EXIT

mkdir -p /run/systemd/system

# Scenario 1: Direct dependency propagation verification
# Unit A is skipped by ExecCondition=, spacer C enforces ordering A→C→B,
# B has BindsTo=A but no direct After=A (to bypass unit_verify_deps).
# Expected: B's start job is cancelled when A is skipped.

cat >/run/systemd/system/test-bindsto-skip.service <<EOF
[Service]
Type=oneshot
ExecCondition=/bin/false
ExecStart=/bin/true
RemainAfterExit=yes
EOF

cat >/run/systemd/system/test-bindsto-spacer.service <<EOF
[Unit]
After=test-bindsto-skip.service
Before=test-bindsto-bound.service

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF

cat >/run/systemd/system/test-bindsto-bound.service <<EOF
[Unit]
BindsTo=test-bindsto-skip.service
Wants=test-bindsto-spacer.service
After=test-bindsto-spacer.service

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF

systemctl daemon-reload

# Start should fail because the BindsTo= dependency was skipped
if systemctl start test-bindsto-bound.service; then
    echo "FAIL: test-bindsto-bound.service should not have started"
    exit 1
fi

# Verify that bound unit is not active
if [[ "$(systemctl is-active test-bindsto-bound.service)" == "active" ]]; then
    echo "FAIL: test-bindsto-bound.service should not be active"
    exit 1
fi

# Verify that skip unit was indeed skipped
if [[ "$(systemctl is-active test-bindsto-skip.service)" == "active" ]]; then
    echo "FAIL: test-bindsto-skip.service should not be active"
    exit 1
fi

condition_result=$(systemctl show -P ConditionResult test-bindsto-skip.service)
if [[ "$condition_result" != "no" ]]; then
    echo "FAIL: test-bindsto-skip.service should have ConditionResult=no, got: $condition_result"
    exit 1
fi

# Scenario 2: Upholds= loop prevention
# Unit A' has Upholds= to B' and is skipped by ExecCondition=.
# Unit B' has BindsTo=A' and After=A'.
# Expected: No restart loop, both units remain inactive.

cat >/run/systemd/system/test-bindsto-upholder.service <<EOF
[Unit]
Upholds=test-bindsto-upheld.service

[Service]
Type=oneshot
ExecCondition=/bin/false
ExecStart=/bin/true
RemainAfterExit=yes
EOF

cat >/run/systemd/system/test-bindsto-upheld.service <<EOF
[Unit]
BindsTo=test-bindsto-upholder.service
After=test-bindsto-upholder.service

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF

systemctl daemon-reload

# Start upholder (may succeed as condition skip is not a hard failure)
systemctl start test-bindsto-upholder.service || true

# Wait a bit to check for loops
sleep 5

# Verify both units are inactive
if [[ "$(systemctl is-active test-bindsto-upholder.service)" == "active" ]]; then
    echo "FAIL: test-bindsto-upholder.service should not be active"
    exit 1
fi

if [[ "$(systemctl is-active test-bindsto-upheld.service)" == "active" ]]; then
    echo "FAIL: test-bindsto-upheld.service should not be active"
    exit 1
fi

# Verify no restart loops occurred
nrestarts_upholder=$(systemctl show -P NRestarts test-bindsto-upholder.service)
nrestarts_upheld=$(systemctl show -P NRestarts test-bindsto-upheld.service)

if [[ "$nrestarts_upholder" != "0" ]]; then
    echo "FAIL: test-bindsto-upholder.service should not have restarted, got NRestarts=$nrestarts_upholder"
    exit 1
fi

if [[ "$nrestarts_upheld" != "0" ]]; then
    echo "FAIL: test-bindsto-upheld.service should not have restarted, got NRestarts=$nrestarts_upheld"
    exit 1
fi

# Verify not in start-limit-hit state
active_state_upholder=$(systemctl show -P ActiveState test-bindsto-upholder.service)
active_state_upheld=$(systemctl show -P ActiveState test-bindsto-upheld.service)

if [[ "$active_state_upholder" == "failed" ]]; then
    echo "FAIL: test-bindsto-upholder.service should not be in failed state"
    exit 1
fi

if [[ "$active_state_upheld" == "failed" ]]; then
    echo "FAIL: test-bindsto-upheld.service should not be in failed state"
    exit 1
fi

echo "All tests passed"
