#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

systemd-analyze set-log-level debug
systemd-analyze set-log-target console

# Create a binary for which execve() will fail
touch /tmp/brokenbinary
chmod +x /tmp/brokenbinary

# These three commands should succeed.
systemd-run --unit=one -p Type=simple /bin/sleep infinity
systemd-run --unit=two -p Type=simple -p User=idontexist /bin/sleep infinity
systemd-run --unit=three -p Type=simple /tmp/brokenbinary

# And now, do the same with Type=exec, where the latter two should fail
systemd-run --unit=four -p Type=exec /bin/sleep infinity
! systemd-run --unit=five -p Type=exec -p User=idontexist /bin/sleep infinity
! systemd-run --unit=six -p Type=exec /tmp/brokenbinary

systemd-analyze set-log-level info

echo OK > /testok

exit 0
