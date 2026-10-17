#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for interactive run0 shells, which are started via the PTY broker if
# possible.

at_exit() {
    set +e
    rm -f /tmp/pty96-run0-*
}

trap at_exit EXIT

# A bare run0 invocation (i.e. without a command) on a TTY starts the user's
# shell. Use a custom $SHELL, so that the shell runs non-interactively and can
# check where it was invoked: the broker places shells in shell-*.service units
# (unlike the D-Bus code path which uses run-*.service). The shell's exit status
# must be propagated.
cat >/tmp/pty96-run0-shell <<'SHELLEOF'
#!/usr/bin/env bash
set -eux
test -t 0; test -t 1; test -t 2
[[ "$(id -u)" == 0 ]]
[[ "$SHELL" == /tmp/pty96-run0-shell ]]
grep -E '/shell-[^/]+\.service$' /proc/self/cgroup
# Like on the D-Bus code path the shell must run in a PAM session, but via the broker's own PAM stack
[[ "$(systemctl show -P PAMName "$(systemctl whoami)")" == systemd-ptybroker-shell ]]
touch /tmp/pty96-run0-ok
exit 7
SHELLEOF
chmod +x /tmp/pty96-run0-shell

script -qec 'run0 --setenv=SHELL=/tmp/pty96-run0-shell' /dev/null </dev/null || RC=$?
[[ "${RC:-0}" == 7 ]]
test -e /tmp/pty96-run0-ok
