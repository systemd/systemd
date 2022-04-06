#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# Note: 'grep ... >/dev/null' instead of just 'grep -q' is used intentionally
#       here, since 'grep -q' exits on the first match causing SIGPIPE being
#       sent to the sender.

BINARY="${1:?}"
export SYSTEMD_LOG_LEVEL=info

if [[ ! -x "$BINARY" ]]; then
    echo "$BINARY is not an executable"
    exit 1
fi

# output width
if "$BINARY" --help | grep -v 'default:' | grep -E '.{80}.' >/dev/null; then
    echo "$(basename "$BINARY") --help output is too wide:"
    "$BINARY" --help | awk 'length > 80' | grep -E --color=yes '.{80}'
    exit 1
fi

# --help prints something. Also catches case where args are ignored.
if ! "$BINARY" --help | grep . >/dev/null; then
    echo "$(basename "$BINARY") --help output is empty"
    exit 2
fi

# no --help output to stderr
if "$BINARY" --help 2>&1 1>/dev/null | grep .; then
    echo "$(basename "$BINARY") --help prints to stderr"
    exit 3
fi

# error output to stderr
if ! ("$BINARY" --no-such-parameter 2>&1 1>/dev/null || :) | grep . >/dev/null; then
    echo "$(basename "$BINARY") with an unknown parameter does not print to stderr"
    exit 4
fi

# --help and -h are equivalent
if ! diff <("$BINARY" -h) <("$BINARY" --help); then
    echo "$(basename "$BINARY") --help and -h are not identical"
    exit 5
fi
