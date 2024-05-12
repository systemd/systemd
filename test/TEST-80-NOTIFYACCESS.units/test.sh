#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

sync_in() {
    read -r x < /tmp/syncfifo2
    test "$x" = "$1"
}

sync_out() {
    echo "$1" > /tmp/syncfifo1
}

export SYSTEMD_LOG_LEVEL=debug

echo "toplevel PID: $BASHPID"

systemd-notify --status="Test starts"
sync_out a
sync_in b
(
    echo "subshell PID: $BASHPID"

    # Make us main process
    systemd-notify --pid="$BASHPID"

    # Lock down access to just us
    systemd-notify "NOTIFYACCESS=main"

    # This should still work
    systemd-notify --status="Sending READY=1 in an unprivileged process"

    # Send as subprocess of the subshell, this should not work
    systemd-notify --ready --pid=self --status "BOGUS1"

    sync_out c
    sync_in d

    # Move main process back to toplevel
    systemd-notify --pid=parent "MAINPID=$$"

    # Should be dropped again
    systemd-notify --status="BOGUS2" --pid=parent

    # Apparently, bash will automatically invoke the last command in a subshell
    # via a simple execve() rather than fork()ing first. But we want that the
    # previous command uses the subshell's PID, hence let's insert a final,
    # bogus redundant command as last command to run in the subshell, so that
    # bash can't optimize things like that.
    echo "bye"
)

echo "toplevel again: $BASHPID"

systemd-notify --ready --status="OK"
systemd-notify "NOTIFYACCESS=none"
systemd-notify --status="BOGUS3"

sync_out e

exec sleep infinity
