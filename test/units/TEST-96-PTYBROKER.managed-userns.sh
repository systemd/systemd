#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# Tests for broker PTYs connected to units running in a managed user namespace with PrivateDevices=yes. Such
# units get their own devpts instance, while the broker allocates the PTY on the host's.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! can_do_rootless_nspawn; then
    echo "Managed user namespaces not supported, skipping."
    exit 77
fi

TTY_GID="$(getent group tty | cut -d: -f3)"

# The broker PTY must remain usable via the standard I/O file descriptors and /dev/tty, and its output
# must still reach the logs. It is not accessible below the unit's /dev/pts/ though, hence ttyname() fails
# for it. PTYs the unit allocates itself belong to the tty group of its user namespace.
systemd-run --wait -u pty96-managed-userns.service \
    -p PrivateUsers=managed -p PrivateDevices=yes \
    -p StandardInput=broker -p StandardOutput=broker-log -p StandardError=broker-log \
    -p SyslogIdentifier=pty96-managed-userns-tag \
    -E TTY_GID="$TTY_GID" \
    bash -xec '
        test -t 0; test -t 1; test -t 2
        : </dev/tty
        if tty; then exit 1; fi
        exec 3<>/dev/ptmx
        [[ "$(stat -c %g /dev/pts/0)" == "$TTY_GID" ]]
        echo hello-pty96-managed-userns-marker'
timeout 30 bash -c 'until journalctl -q -t pty96-managed-userns-tag | grep hello-pty96-managed-userns-marker >/dev/null; do journalctl --sync; sleep 1; done'
wait_for_pty_deregistration pty96-managed-userns.service
