#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

# Note: 'grep ... >/dev/null' instead of just 'grep -q' is used intentionally
#       here, since 'grep -q' exits on the first match causing SIGPIPE being
#       sent to the sender.

BINARY="${1:?}"
export SYSTEMD_LOG_LEVEL=info

# Sanitizer runtime warnings are not program output, so drop them before checking that a binary
# keeps its stderr clean. Binaries that run their main function on a fiber make ASan warn about
# makecontext()/swapcontext() and about ignoring __asan_handle_no_return. Only WARNING lines are
# filtered, an actual ==pid==ERROR: report still counts as output.
drop_sanitizer_warnings() {
    grep -v -e '^==[0-9]*==WARNING: ' \
            -e '^False positive error reports may follow$' \
            -e '^For details see https://github.com/google/sanitizers/'
}

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
if "$BINARY" --help 2>&1 1>/dev/null | drop_sanitizer_warnings | grep .; then
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
