#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

COUNTER_FILE=/tmp/test-03-restart-counter

COUNT="$(<"$COUNTER_FILE")"
: $(( COUNT++ ))
echo "$COUNT" >"$COUNTER_FILE"

systemd-notify --ready

sleep infinity
