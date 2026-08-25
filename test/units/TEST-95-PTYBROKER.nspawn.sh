#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for "systemd-nspawn --console=broker|broker-log": the container console is
# enrolled with systemd-ptybrokerd instead of being connected to the invoking TTY.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v systemd-nspawn >/dev/null || [[ ! -d /usr/share/TEST-13-NSPAWN-container-template ]]; then
    echo "systemd-nspawn or the container template not available, skipping." >&2
    exit 77
fi

ROOT=/var/lib/machines/pty95-nspawn

at_exit() {
    set +e
    rm -fr "$ROOT" /run/systemd/nspawn/pty95-nspawn.nspawn
}

trap at_exit EXIT

create_dummy_container "$ROOT"

# Run a one-off command with the console registered with the broker in log mode.
# nspawn reports the (randomly chosen) registration name on stderr; the payload's
# console output must end up in the journal under that name.
OUT="$(systemd-nspawn -D "$ROOT" --machine=pty95-nspawn --register=no --console=broker-log sh -xc 'echo hello-pty95-nspawn-marker' 2>&1)"
NAME="$(sed -n "s/.*Broker registered console pseudo TTY under name '\([^']*\)'.*/\1/p" <<<"$OUT")"
test -n "$NAME"

timeout 30 bash -c "until journalctl -q -t '$NAME' | grep hello-pty95-nspawn-marker >/dev/null; do journalctl --sync; sleep 1; done"

# The registration must be gone again now that the container exited
wait_for_pty_deregistration "$NAME"
