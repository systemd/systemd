#!/usr/bin/env bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex

mkdir -p /tmp/img/usr/lib/systemd/system
cp /usr/lib/os-release /tmp/img/usr/lib/
cat > /tmp/img/usr/lib/systemd/system/testservice-49.target <<EOF
[Unit]
Description=I am portable!
EOF

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

portablectl attach --copy=symlink --runtime --now --no-reload /tmp/img testservice-49

systemctl is-active testservice-49.target

portablectl detach --runtime --now --no-reload /tmp/img testservice-49
rm -rf /tmp/img

systemctl status testservice-49.target |& grep -q "Unit testservice-49.target could not be found"

echo OK > /testok

exit 0
