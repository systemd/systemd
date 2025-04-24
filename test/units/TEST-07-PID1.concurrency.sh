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

rm /run/systemd/system/concurrency1.slice
rm /run/systemd/system/concurrency1-concurrency2.slice
rm /run/systemd/system/concurrency1-concurrency3.slice
rm /run/systemd/system/sleepforever1@.service
rm /run/systemd/system/sync-on-sleepforever1@.service
rm /run/systemd/system/sleepforever2@.service
rm /run/systemd/system/sleepforever3@.service

systemctl daemon-reload
