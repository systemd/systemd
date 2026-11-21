#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for interactive run0 shells, which are started via the PTY broker if
# possible.

at_exit() {
    set +e
    systemctl start systemd-ptybrokerd.socket
    rm -f /tmp/pty96-run0-*
}

trap at_exit EXIT

# A bare run0 invocation (i.e. without a command) on a TTY starts the user's
# shell. Use a custom $SHELL, so that the shell runs non-interactively and can
# check how it was invoked: the broker uses its own PAM stack and places shells in
# shell-*.service units (unlike the D-Bus code path which uses run-*.service). The
# shell's exit status must be propagated.
cat >/tmp/pty96-run0-shell <<'SHELLEOF'
#!/usr/bin/env bash
set -eux
test -t 0; test -t 1; test -t 2
[[ "$(id -u)" == 0 ]]
[[ "$SHELL" == /tmp/pty96-run0-shell ]]
# Like on the D-Bus code path the shell runs in a PAM session (and hence is moved into the session scope by
# logind), but via the broker's own PAM stack, rather than systemd-run0's
[[ "$(loginctl show-session "$XDG_SESSION_ID" -P Service)" == systemd-ptybroker-shell ]]
systemctl list-units --no-legend 'shell-*.service' | grep . >/dev/null
echo pty96-forwarded
touch /tmp/pty96-run0-ok
exit 7
SHELLEOF
chmod +x /tmp/pty96-run0-shell

# The same shell, but with checks for the D-Bus code path that run0 falls back to when the broker
# is not available: the shell is placed in a run-*.service unit, in a PAM session of systemd-run0's
# own PAM stack.
cat >/tmp/pty96-run0-shell-dbus <<'SHELLEOF'
#!/usr/bin/env bash
set -eux
test -t 0; test -t 1; test -t 2
[[ "$(id -u)" == 0 ]]
[[ "$SHELL" == /tmp/pty96-run0-shell-dbus ]]
[[ "$(loginctl show-session "$XDG_SESSION_ID" -P Service)" == systemd-run0 ]]
systemctl list-units --no-legend 'run-*.service' | grep . >/dev/null
echo pty96-forwarded
touch /tmp/pty96-run0-ok
exit 7
SHELLEOF
chmod +x /tmp/pty96-run0-shell-dbus

run0_test() {
    local option=$1 shell=$2 output rc=0

    output=$(script -qec "run0 ${option} --setenv=SHELL=${shell}" /dev/null </dev/null) || rc=$?
    [[ "$rc" == 7 ]]
    [[ "$output" == *pty96-forwarded* ]]
    test -e /tmp/pty96-run0-ok
    rm -f /tmp/pty96-run0-ok
}

# run0 defaults to --pty-late unless --no-ask-password is specified.
run0_test "" /tmp/pty96-run0-shell
run0_test --pty /tmp/pty96-run0-shell

# When the broker is not available run0 must fall back to the D-Bus code path. Stop
# systemd-ptybrokerd.socket and .service to simulate that.
systemctl stop systemd-ptybrokerd.socket systemd-ptybrokerd.service
run0_test "" /tmp/pty96-run0-shell-dbus
run0_test --pty /tmp/pty96-run0-shell-dbus
systemctl start systemd-ptybrokerd.socket
