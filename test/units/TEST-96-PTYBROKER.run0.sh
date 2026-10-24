#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for interactive run0 shells, which are started via the PTY broker if
# possible.

holders=()

at_exit() {
    set +e
    if [[ ${#holders[@]} -gt 0 ]]; then
        kill "${holders[@]}"
        wait "${holders[@]}"
    fi
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
touch /tmp/pty96-run0-ok
exit 7
SHELLEOF
chmod +x /tmp/pty96-run0-shell

script -qec 'run0 --setenv=SHELL=/tmp/pty96-run0-shell' /dev/null </dev/null || RC=$?
[[ "${RC:-0}" == 7 ]]
test -e /tmp/pty96-run0-ok

# The reference FD must outlive the PTY and remain valid across manager reload and reexecution.
# shellcheck disable=SC2016
timeout 60 varlinkctl --exec call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.AcquirePty \
    '{"frontendType":"null","backendType":"shell","viaShell":false,"commandLine":["/bin/sh","-c","exit 47"],"referenceUnit":true}' \
    -- bash -euxc '
        read -r unit reference < <(jq -er "[.unit, .unitReferenceFileDescriptor] | @tsv")
        [[ "$LISTEN_FDS" == 1 && "$reference" == 0 ]]
        until [[ "$(systemctl show -P ActiveState "$unit")" == failed ]]; do sleep .1; done
        for operation in daemon-reload daemon-reexec; do
            systemctl "$operation"
            [[ "$(systemctl show -P ExecMainStatus "$unit")" == 47 ]]
        done
        exec 3>&-
        until [[ "$(systemctl show -P LoadState "$unit")" == not-found ]]; do sleep .1; done
    '

# More references than PID 1's 128-per-UID connection limit must not exhaust its root connections.
for i in {1..130}; do
    ready="/tmp/pty96-run0-reference-$i"
    # shellcheck disable=SC2016
    varlinkctl --exec call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.AcquirePty \
        '{"frontendType":"null","backendType":"shell","viaShell":false,"commandLine":["/bin/true"],"referenceUnit":true}' \
        -- bash -ec 'jq -er .unit >"$1"; exec sleep infinity' _ "$ready" &
    holders+=("$!")
    # shellcheck disable=SC2016
    timeout 10 bash -ec 'until test -s "$1"; do kill -0 "$2"; sleep .1; done' _ "$ready" "$!"
done
systemctl daemon-reexec
varlinkctl --quiet call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}'
kill "${holders[0]}"
wait "${holders[0]}" || :
unset 'holders[0]'
unit=$(</tmp/pty96-run0-reference-1)
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show -P LoadState "$1")" == not-found ]]; do sleep .1; done' _ "$unit"
unit=$(</tmp/pty96-run0-reference-130)
[[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
kill "${holders[@]}"
wait "${holders[@]}" || :
holders=()
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show -P LoadState "$1")" == not-found ]]; do sleep .1; done' _ "$unit"

# run0 must still work when the broker is not installed or its socket is disabled.
systemctl stop systemd-ptybrokerd.service systemd-ptybrokerd.socket
[[ "$(run0 --pty echo -n foo)" == foo ]]
systemctl start systemd-ptybrokerd.socket
