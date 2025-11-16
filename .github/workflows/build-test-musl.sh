#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

if ! command -v musl-gcc >/dev/null; then
    echo "musl-gcc is not installed, skipping the test."
    exit 77
fi

TMPDIR=$(mktemp -d)

cleanup() (
    set +e

    if [[ -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
)

trap cleanup EXIT ERR INT TERM

tools/setup-musl-build.sh "${TMPDIR}/build"
ninja -v -C "${TMPDIR}/build"
