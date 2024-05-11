#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

# Test start & stop operations without daemon-reload

at_exit() {
    set +e

    rm -f /run/systemd/system/TEST-23-UNIT-FILE-no-reload.{service,target}
}

trap at_exit EXIT

cat >/run/systemd/system/TEST-23-UNIT-FILE-no-reload.target <<EOF
[Unit]
Wants=TEST-23-UNIT-FILE-no-reload.service
EOF

systemctl daemon-reload

systemctl start TEST-23-UNIT-FILE-no-reload.target

# The filesystem on the test image, despite being ext4, seems to have a mtime
# granularity of one second, which means the manager's unit cache won't be
# marked as dirty when writing the unit file, unless we wait at least a full
# second after the previous daemon-reload.
# May 07 23:12:20 H TEST-23-UNIT-FILE.sh[30]: + cat
# May 07 23:12:20 H TEST-23-UNIT-FILE.sh[30]: + ls -l --full-time /etc/systemd/system/TEST-23-UNIT-FILE-no-reload.service
# May 07 23:12:20 H TEST-23-UNIT-FILE.sh[52]: -rw-r--r-- 1 root root 50 2020-05-07 23:12:20.000000000 +0100 /
# May 07 23:12:20 H TEST-23-UNIT-FILE.sh[30]: + stat -f --format=%t /etc/systemd/system/TEST-23-UNIT-FILE-no-reload.servic
# May 07 23:12:20 H TEST-23-UNIT-FILE.sh[53]: ef53
sleep 3.1

cat >/run/systemd/system/TEST-23-UNIT-FILE-no-reload.service <<EOF
[Service]
ExecStart=sleep infinity
EOF

systemctl start TEST-23-UNIT-FILE-no-reload.service

systemctl is-active TEST-23-UNIT-FILE-no-reload.service

# Stop and remove, and try again to exercise https://github.com/systemd/systemd/issues/15992
systemctl stop TEST-23-UNIT-FILE-no-reload.service
rm -f /run/systemd/system/TEST-23-UNIT-FILE-no-reload.service
systemctl daemon-reload

sleep 3.1

cat >/run/systemd/system/TEST-23-UNIT-FILE-no-reload.service <<EOF
[Service]
ExecStart=sleep infinity
EOF

# Start a non-existing unit first, so that the cache is reloaded for an unrelated
# reason. Starting the existing unit later should still work thanks to the check
# for the last load attempt vs cache timestamp.
systemctl start TEST-23-UNIT-FILE-no-reload-nonexistent.service || true

systemctl start TEST-23-UNIT-FILE-no-reload.service

systemctl is-active TEST-23-UNIT-FILE-no-reload.service

# Stop and remove, and try again to exercise the transaction setup code path by
# having the target pull in the unloaded but available unit
systemctl stop TEST-23-UNIT-FILE-no-reload.service TEST-23-UNIT-FILE-no-reload.target
rm -f /run/systemd/system/TEST-23-UNIT-FILE-no-reload.service /run/systemd/system/TEST-23-UNIT-FILE-no-reload.target
systemctl daemon-reload

sleep 3.1

cat >/run/systemd/system/TEST-23-UNIT-FILE-no-reload.target <<EOF
[Unit]
Conflicts=shutdown.target
Wants=TEST-23-UNIT-FILE-no-reload.service
EOF

systemctl daemon-reload

systemctl start TEST-23-UNIT-FILE-no-reload.target

cat >/run/systemd/system/TEST-23-UNIT-FILE-no-reload.service <<EOF
[Service]
ExecStart=sleep infinity
EOF

systemctl restart TEST-23-UNIT-FILE-no-reload.target

systemctl is-active TEST-23-UNIT-FILE-no-reload.service
