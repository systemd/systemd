#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

systemctl disable --now systemd-timesyncd.service

timedatectl set-timezone Europe/Berlin
timedatectl set-time 1980-10-15

systemd-run --on-timezone-change touch /tmp/timezone-changed
systemd-run --on-clock-change touch /tmp/clock-changed

! test -f /tmp/timezone-changed
! test -f /tmp/clock-changed

timedatectl set-timezone Europe/Kiev

while ! test -f /tmp/timezone-changed ; do sleep .5 ; done

timedatectl set-time 2018-1-1

while ! test -f /tmp/clock-changed ; do sleep .5 ; done

systemd-analyze log-level info

echo OK > /testok

exit 0
