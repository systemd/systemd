#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# Note: 'grep ... >/dev/null' instead of just 'grep -q' is used intentionally
#       here, since 'grep -q' exits on the first match causing SIGPIPE being
#       sent to the sender.

BINARY="${1:?}"
VERSION="${2:?}"
export SYSTEMD_LOG_LEVEL=info

if [[ ! -x "$BINARY" ]]; then
    echo "$BINARY is not an executable"
    exit 1
fi

# --version prints something. Also catches case where args are ignored.
if ! "$BINARY" --version | grep . >/dev/null; then
    echo "$(basename "$BINARY") --version output is empty"
    exit 2
fi

# no --version output to stderr
if "$BINARY" --version 2>&1 1>/dev/null | grep .; then
    echo "$(basename "$BINARY") --version prints to stderr"
    exit 3
fi

# project version appears in version output
out="$("$BINARY" --version)"
if ! grep -F "$VERSION" >/dev/null <<<"$out"; then
    echo "$(basename "$BINARY") --version output does not match '$VERSION': $out"
    exit 4
fi
