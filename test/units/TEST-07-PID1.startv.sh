#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-run -v --wait echo wampfl | grep wampfl

systemd-run -v --service-type=notify bash -c 'echo brumfl ; systemd-notify --ready ; echo krass' | grep brumfl

mkdir -p /run/systemd/journald.conf.d/

# Let's disable storage of debug messages, since we want to flood the journal
# daemon with messages that it will have to process, but we do not actually
# want to push out our own messages from storage while doing so
cat >> /run/systemd/journald.conf.d/50-disable-debug.conf <<EOF
[Journal]
MaxLevelStore=info
EOF

systemctl restart systemd-journald

# Now flood the journal via syslog and the stream transport to ensure this finishes correctly even if busy
( xxd /dev/urandom | logger -p debug ) &
( xxd /dev/urandom | systemd-cat -p debug ) &

# Verify that this works even if the journal is super busy
systemd-run -v --service-type=notify bash -c 'echo schmurz ; systemd-notify --ready ; echo kropf' | grep schmurz

kill %1
kill %2

# Flush pending journal entries
systemd-run --unit=marker-hogefoo.service --service-type=notify bash -c 'journalctl --follow | grep -m1 marker_hogefoo'
systemd-run --unit=marker-hogebar.service --service-type=notify bash -c 'journalctl --follow | grep -m1 marker_hogebar'
echo marker_hogefoo | logger -p debug
echo marker_hogebar | systemd-cat -p debug
timeout 30 bash -c 'while systemctl is-active marker-hogefoo.service; do sleep 1; done'
timeout 30 bash -c 'while systemctl is-active marker-hogebar.service; do sleep 1; done'
journalctl --sync

rm /run/systemd/journald.conf.d/50-disable-debug.conf
rmdir --ignore-fail-on-non-empty /run/systemd/journald.conf.d

systemctl restart systemd-journald
