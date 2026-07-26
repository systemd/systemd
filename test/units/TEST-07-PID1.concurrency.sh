#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

cat >/run/systemd/system/concurrency1.slice <<EOF
[Slice]
ConcurrencyHardMax=4
ConcurrencySoftMax=3
EOF

cat >/run/systemd/system/sleepforever1@.service <<EOF
[Service]
Slice=concurrency1.slice
ExecStart=sleep infinity
EOF

cat >/run/systemd/system/sync-on-sleepforever1@.service <<EOF
[Unit]
After=sleepforever1@%i.service

[Service]
ExecStart=true
EOF

cat >/run/systemd/system/concurrency1-concurrency2.slice <<EOF
[Slice]
ConcurrencySoftMax=1
EOF

cat >/run/systemd/system/sleepforever2@.service <<EOF
[Service]
Slice=concurrency1-concurrency2.slice
ExecStart=sleep infinity
EOF
cat >/run/systemd/system/concurrency1-concurrency3.slice <<EOF
[Slice]
ConcurrencySoftMax=1
EOF

cat >/run/systemd/system/sleepforever3@.service <<EOF
[Service]
Slice=concurrency1-concurrency3.slice
ExecStart=sleep infinity
EOF

systemctl daemon-reload

systemctl status concurrency1.slice ||:
(! systemctl is-active concurrency1.slice)
systemctl start sleepforever1@a.service
systemctl is-active concurrency1.slice
systemctl status concurrency1.slice
systemctl show concurrency1.slice
systemctl start sleepforever1@b.service
systemctl status concurrency1.slice
systemctl start sleepforever1@c.service
systemctl status concurrency1.slice

# The fourth call should hang because the soft limit is hit, verify that
timeout 1s systemctl start sleepforever1@d.service && test "$?" -eq 124
systemctl status concurrency1.slice
systemctl list-jobs

systemctl is-active sleepforever1@a.service
systemctl is-active sleepforever1@b.service
systemctl is-active sleepforever1@c.service
(! systemctl is-active sleepforever1@d.service)
systemctl status concurrency1.slice

# Now stop one, which should trigger the queued unit immediately
systemctl stop sleepforever1@b.service

# the 'd' instance should still be queued, now sync on it via another unit (which doesn't pull it in again, but is ordered after it)
systemctl start sync-on-sleepforever1@d.service

systemctl is-active sleepforever1@a.service
(! systemctl is-active sleepforever1@b.service)
systemctl is-active sleepforever1@c.service
systemctl is-active sleepforever1@d.service

# A fifth one should immediately fail because of the hard limit once we re-enqueue the fourth
systemctl --no-block start sleepforever1@b.service
(! systemctl start sleepforever1@e.service)

systemctl stop sleepforever1@b.service
systemctl stop sleepforever1@c.service
systemctl stop sleepforever1@d.service

# Now go for some nesting
systemctl start sleepforever2@a.service
systemctl is-active sleepforever2@a.service
systemctl is-active concurrency1-concurrency2.slice
systemctl status concurrency1.slice
systemctl status concurrency1-concurrency2.slice

# This service is in a sibling slice. Should be delayed
timeout 1s systemctl start sleepforever3@a.service && test "$?" -eq 124

# And the hard limit should make the next job completely fail
(! systemctl start sleepforever3@b.service)

# Stopping one service should not suffice to make the service run, because we need two slots: for slice and service
systemctl stop sleepforever2@a.service
timeout 1s systemctl start sleepforever3@a.service && test "$?" -eq 124

# Stopping one more slice should be enough though
systemctl stop concurrency1-concurrency2.slice
systemctl start sleepforever3@a.service

systemctl stop concurrency1.slice
systemctl reset-failed

# Test ActivatingConcurrencyMax
cat >/run/systemd/system/concurrency-activating.slice <<EOF
[Slice]
ActivatingConcurrencyMax=2
EOF

cat >/run/systemd/system/slow-start@.service <<EOF
[Service]
Slice=concurrency-activating.slice
# Simulate slow startup
ExecStartPre=/usr/bin/sleep 2
ExecStart=/usr/bin/sleep infinity
EOF

systemctl daemon-reload

# Start 3 services - only 2 should activate concurrently
systemctl --no-block start slow-start@a.service
systemctl --no-block start slow-start@b.service
systemctl --no-block start slow-start@c.service

# Wait for jobs to be dispatched and first two to enter activating
for _ in {1..20}; do
    jobs=$(systemctl list-jobs | grep -c "slow-start@.*start" || true)
    if [[ "$jobs" -eq 3 ]]; then
        activating=$(systemctl list-units --state=activating 'slow-start@*' --no-legend | wc -l)
        if [[ "$activating" -eq 2 ]]; then
            break
        fi
    fi
    sleep 0.1
done

# Check that exactly 2 are activating (c should be queued)
test "$(systemctl list-jobs | grep -c "slow-start@.*start")" -eq 3
test "$(systemctl show -p ActiveState slow-start@a.service --value)" = "activating"
test "$(systemctl show -p ActiveState slow-start@b.service --value)" = "activating"
test "$(systemctl show -p ActiveState slow-start@c.service --value)" = "inactive"

# Wait for a and b to finish starting, then c to start and finish
# a,b take ~2s to activate, then c starts and takes ~2s more
sleep 5

# Now all should be active (c started when a/b finished activating)
systemctl is-active slow-start@a.service
systemctl is-active slow-start@b.service
systemctl is-active slow-start@c.service

# Cleanup
systemctl stop concurrency-activating.slice
systemctl reset-failed
rm /run/systemd/system/concurrency-activating.slice
rm /run/systemd/system/slow-start@.service

systemctl daemon-reload

# Final cleanup of original tests
systemctl reset-failed

rm /run/systemd/system/concurrency1.slice
rm /run/systemd/system/concurrency1-concurrency2.slice
rm /run/systemd/system/concurrency1-concurrency3.slice
rm /run/systemd/system/sleepforever1@.service
rm /run/systemd/system/sync-on-sleepforever1@.service
rm /run/systemd/system/sleepforever2@.service
rm /run/systemd/system/sleepforever3@.service

systemctl daemon-reload
