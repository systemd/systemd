#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-run -v --wait echo wampfl | grep wampfl

systemd-run -v -p Type=notify bash -c 'echo brumfl ; systemd-notify --ready ; echo krass' |  grep brumfl

# Now flood the journal via syslog and the stream transport to ensure this finishes correctly even if busy
( xxd /dev/urandom | logger ) &
( xxd /dev/urandom | systemd-cat ) &

# Verify that this works even if the journal is super busy
systemd-run -v -p Type=notify bash -c 'echo schmurz ; systemd-notify --ready ; echo kropf' |  grep schmurz

kill %1
kill %2
