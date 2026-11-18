#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for interactive run0 shells, which are started via the PTY broker if
# possible.

holders=()
units=()
manager_redirected=no

at_exit() {
    set +e
    if [[ "$manager_redirected" == yes ]]; then
        nsenter --target="$broker_pid" --mount -- umount /run/systemd/io.systemd.Manager
    fi
    if [[ ${#holders[@]} -gt 0 ]]; then
        kill "${holders[@]}"
        wait "${holders[@]}"
    fi
    if [[ ${#units[@]} -gt 0 ]]; then
        systemctl stop "${units[@]}"
    fi
    systemctl start systemd-ptybrokerd.socket
    rm -f /tmp/pty96-run0-*
}

trap at_exit EXIT

start_watch() {
    local name=$1 ready="/tmp/pty96-run0-watch-$1"
    varlinkctl -E --json=short call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.WatchPty \
        "{\"name\":\"$name\",\"wait\":true}" >"$ready" &
    holders+=("$!")
    # shellcheck disable=SC2016
    timeout 10 bash -ec 'until grep -F "\"state\":\"reserved\"" "$1" >/dev/null; do kill -0 "$2"; sleep .1; done' _ "$ready" "$!"
}

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

# A watch established before allocation pins even a short-lived shell through reload and reexecution.
start_watch pty96-status
unit=$(varlinkctl call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.AcquirePty \
    '{"name":"pty96-status","frontendType":"null","backendType":"shell","viaShell":false,"commandLine":["/bin/sh","-c","while ! test -e /tmp/pty96-run0-finish; do sleep .1; done; exit 47"]}' \
    | jq -er .unit)
# shellcheck disable=SC2016
timeout 10 bash -c 'until jq --seq --slurp -e "any(.[]; .state == \"running\")" "$1" >/dev/null; do sleep .1; done' _ /tmp/pty96-run0-watch-pty96-status
varlinkctl call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.ListPty \
    '{"name":"pty96-status"}' >/tmp/pty96-run0-description
jq --seq --slurp --slurpfile listed /tmp/pty96-run0-description \
    -e 'map(.state) == ["reserved", "acquiring", "running"] and any(.[]; . == $listed[0])' /tmp/pty96-run0-watch-pty96-status
touch /tmp/pty96-run0-finish
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show -P ActiveState "$1")" == failed ]]; do sleep .1; done' _ "$unit"
# shellcheck disable=SC2016
timeout 10 bash -c 'until jq --seq --slurp -e "any(.[]; .state == \"hung_up\")" "$1" >/dev/null; do sleep .1; done' _ /tmp/pty96-run0-watch-pty96-status
varlinkctl --graceful=io.systemd.PTYBroker.NoSuchPty call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.ListPty \
    '{"name":"pty96-status"}' | jq -e 'length == 0'
for operation in daemon-reload daemon-reexec; do
    systemctl "$operation"
    [[ "$(systemctl show -P ExecMainStatus "$unit")" == 47 ]]
done
kill "${holders[0]}"
wait "${holders[0]}" || :
holders=()
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show -P LoadState "$1")" == not-found ]]; do sleep .1; done' _ "$unit"

# Each shell holds its own PID 1 connection. Root is exempt from the 128-per-UID limit.
for i in {1..130}; do
    name="pty96reference$i"
    ready="/tmp/pty96-run0-reference-$i"
    # --upgrade to bash allows avoiding a pam session being kept alive per reference, which costs too much
    # memory under ASAN
    # shellcheck disable=SC2016
    varlinkctl --upgrade --exec call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.AcquirePty \
        "{\"name\":\"$name\",\"frontendType\":\"null\",\"backendType\":\"shell\",\"viaShell\":false,\"commandLine\":[\"/usr/bin/true\"],\"monitor\":true,\"hangUpOnDisconnect\":true,\"ignoreHangup\":true}" \
        -- bash -ec 'touch "$1"; exec sleep infinity' _ "$ready" &
    holders+=("$!")
    # shellcheck disable=SC2016
    timeout 10 bash -ec 'until test -e "$1"; do kill -0 "$2"; sleep .1; done' _ "$ready" "$!"
    unit="shell-$name.service"
    units+=("$unit")
    # shellcheck disable=SC2016
    timeout 10 bash -ec 'until [[ "$(systemctl show -P ActiveState "$1")" == inactive ]]; do sleep .1; done' _ "$unit"
done
systemctl daemon-reexec
varlinkctl --quiet call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}'
for unit in "${units[@]}"; do
    [[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
done

# Reject new AcquireReference calls without disconnecting any of the established unit references.
broker_pid=$(systemctl show -P MainPID systemd-ptybrokerd.service)
broker_socket=$(stat -Lc '%d:%i' /run/systemd/io.systemd.PTYBroker)
systemctl bind systemd-ptybrokerd.service /run/systemd/io.systemd.PTYBroker /run/systemd/io.systemd.Manager
manager_redirected=yes
varlinkctl --graceful=io.systemd.System call /run/systemd/io.systemd.PTYBroker io.systemd.PTYBroker.AcquirePty \
    '{"frontendType":"null","backendType":"shell","viaShell":false,"commandLine":["/bin/true"]}' \
    | jq -e '.errno == 6' >/dev/null # ENXIO: AcquireReference is not implemented by the replacement endpoint.
# Remove the injected mount; overmounting it can propagate onto the source socket on older kernels.
nsenter --target="$broker_pid" --mount -- umount /run/systemd/io.systemd.Manager
manager_redirected=no
[[ "$(stat -Lc '%d:%i' /run/systemd/io.systemd.PTYBroker)" == "$broker_socket" ]]
systemctl daemon-reexec
[[ "$(systemctl show -P LoadState "${units[129]}")" == loaded ]]

unit=${units[0]}
kill "${holders[0]}"
wait "${holders[0]}" || :
unset 'holders[0]'
unset 'units[0]'
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show -P LoadState "$1")" == not-found ]]; do sleep .1; done' _ "$unit"
unit=${units[129]}
[[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
kill "${holders[@]}"
wait "${holders[@]}" || :
holders=()
units=()
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show -P LoadState "$1")" == not-found ]]; do sleep .1; done' _ "$unit"

# run0 must still work when the broker is not installed or its socket is disabled.
systemctl stop systemd-ptybrokerd.service systemd-ptybrokerd.socket
[[ "$(run0 --pty echo -n foo)" == foo ]]
systemctl start systemd-ptybrokerd.socket
