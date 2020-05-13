#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex

cat > /run/systemd/system/testservice-48.target <<EOF
[Unit]
Wants=testservice-48.service
EOF

systemctl daemon-reload

systemctl start testservice-48.target

# The filesystem on the test image, despite being ext4, seems to have a mtime
# granularity of one second, which means the manager's unit cache won't be
# marked as dirty when writing the unit file, unless we wait at least a full
# second after the previous daemon-reload.
# May 07 23:12:20 systemd-testsuite testsuite-48.sh[30]: + cat
# May 07 23:12:20 systemd-testsuite testsuite-48.sh[30]: + ls -l --full-time /etc/systemd/system/testservice-48.service
# May 07 23:12:20 systemd-testsuite testsuite-48.sh[52]: -rw-r--r-- 1 root root 50 2020-05-07 23:12:20.000000000 +0100 /
# May 07 23:12:20 systemd-testsuite testsuite-48.sh[30]: + stat -f --format=%t /etc/systemd/system/testservice-48.servic
# May 07 23:12:20 systemd-testsuite testsuite-48.sh[53]: ef53
sleep 1.1

cat > /run/systemd/system/testservice-48.service <<EOF
[Service]
ExecStart=/bin/sleep infinity
Type=exec
EOF

systemctl start testservice-48.service

systemctl is-active testservice-48.service

systemctl stop --job-mode replace-unload testservice-48.service

rm -f /run/systemd/system/testservice-48.service

systemctl status testservice-48.service |& grep -q "Unit testservice-48.service could not be found"

echo OK > /testok

exit 0
