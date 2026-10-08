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

# --version prints something. Also catches case where args are ignored.
if ! "$BINARY" --version | grep . >/dev/null; then
    echo "$(basename "$BINARY") --version output is empty"
    exit 2
fi

# no --version output to stderr
if "$BINARY" --version 2>&1 1>/dev/null | drop_sanitizer_warnings | grep .; then
    echo "$(basename "$BINARY") --version prints to stderr"
    exit 3
fi

# project version appears in version output
out="$("$BINARY" --version)"
if ! grep -F "$VERSION" >/dev/null <<<"$out"; then
    echo "$(basename "$BINARY") --version output does not match '$VERSION': $out"
    exit 4
fi
