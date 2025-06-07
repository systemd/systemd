#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

PINNED="$1"
COUNTER="/tmp/fdstore-invoked.$PINNED"
FILE="/tmp/fdstore-data.$PINNED"

# This script is called six times: thrice from a service unit where the fdstore
# is pinned, and thrice where it isn't. The second iteration of each series is
# a restart, the third a stop followed by a start

if [ -e "$COUNTER" ] ; then
    read -r N < "$COUNTER"
else
    N=0
fi

echo "Invocation #$N with PINNED=$PINNED."

if [ "$N" -eq 0 ] ; then
    # First iteration
    test "${LISTEN_FDS:-0}" -eq 0
    test ! -e "$FILE"
    echo waldi > "$FILE"
    systemd-notify --fd=3 --fdname="fd-$N-$PINNED" 3< "$FILE"
elif [ "$N" -eq 1 ] || { [ "$N" -eq 2 ] && [ "$PINNED" -eq 1 ]; } ; then
    # Second iteration, or iteration with pinning on
    test "${LISTEN_FDS:-0}" -eq 1
    # We reopen fd #3 here, so that the read offset is at zero each time (hence no <&3 here…)
    read -r word < /proc/self/fd/3
    test "$word" = "waldi"
else
    test "${LISTEN_FDS:-0}" -eq 0
    test -e "$FILE"
fi

if [ "$N" -ge 2 ] ; then
    rm "$COUNTER" "$FILE"
else
    echo $((N + 1)) > "$COUNTER"
fi

systemd-notify --ready --status="Ready"

exec sleep infinity
