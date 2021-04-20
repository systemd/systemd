#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

BINARY="${1:?}"
export SYSTEMD_LOG_LEVEL=info

# output width
if "$BINARY" --help | grep -v 'default:' | grep -E -q '.{80}.'; then
    echo "$(basename "$BINARY") --help output is too wide:"
    "$BINARY"  --help | awk 'length > 80' | grep -E --color=yes '.{80}'
    exit 1
fi

# --help prints something. Also catches case where args are ignored.
if ! "$BINARY" --help | grep -q .; then
    echo "$(basename "$BINARY") --help output is empty."
    exit 2
fi

# no --help output to stdout
if "$BINARY" --help 2>&1 1>/dev/null | grep .; then
    echo "$(basename "$BINARY") --help prints to stderr"
    exit 3
fi

# error output to stderr
if ! ("$BINARY" --no-such-parameter 2>&1 1>/dev/null || :) | grep -q .; then
    echo "$(basename "$BINARY") with an unknown parameter does not print to stderr"
    exit 4
fi
