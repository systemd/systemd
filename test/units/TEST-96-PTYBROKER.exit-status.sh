#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests for TTYExitStatus=: when the TTY is passed in as file descriptors (as "systemd-run --pty" and the
# broker's shell units do), the executor opens an OSC 3008 service context on it and pid1 closes that context
# with the exit status once the service is dead, so that the status travels in-band on the TTY.

at_exit() {
    set +e
    systemctl reset-failed 'pty96-exit-*.service'
    rm -f /tmp/pty96-exit-*
}

trap at_exit EXIT

# Runs the command via "systemd-run --pty" under script(1), so that the raw bytes the pty produces (OSC
# sequences included) end up in the given file. The service's exit status is of no interest here.
run_pty() {
    local out="${1:?}"
    shift

    script -qec "systemd-run --quiet --pty --wait $(printf '%q ' "$@")" "$out" </dev/null >/dev/null || :
}

# Asserts that the capture holds a start record for the given unit (an ERE) and an end record with the given
# exit fields. The context id ties the two together, and an ESC can not occur inside a record, hence
# everything matched between the markers belongs to the same sequence.
assert_exit_record() {
    local out="${1:?}" unit="${2:?}" exit_fields="${3:?}" start id

    start="$(grep -aoE $'\e]3008;start=[0-9a-f]{32}[^\e]*;servicename='"$unit"$'[^\e]*;type=service\e\\\\' "$out")"
    [[ -n "$start" ]]
    id="$(sed -E 's/.*start=([0-9a-f]{32}).*/\1/' <<<"$start")"
    grep -aF "3008;end=$id;$exit_fields"$'\e\\' "$out"
}

run_pty /tmp/pty96-exit-success -u pty96-exit-success.service -p TTYExitStatus=yes true
assert_exit_record /tmp/pty96-exit-success pty96-exit-success.service 'exit=success;status=0'

run_pty /tmp/pty96-exit-failure -u pty96-exit-failure.service -p TTYExitStatus=yes sh -c 'exit 3'
assert_exit_record /tmp/pty96-exit-failure pty96-exit-failure.service 'exit=failure;status=3'

# pid1 collapses $$ in command lines to a single $, hence the doubling
# shellcheck disable=SC2016
run_pty /tmp/pty96-exit-signal -u pty96-exit-signal.service -p TTYExitStatus=yes sh -c 'kill -TERM $$$$'
assert_exit_record /tmp/pty96-exit-signal pty96-exit-signal.service 'exit=interrupt;signal=SIGTERM'

# Without TTYExitStatus= (and without TTYReset=) no context is opened at all, hence nothing may be closed
# with an exit status either
run_pty /tmp/pty96-exit-plain -u pty96-exit-plain.service true
(! grep -aF '3008;start=' /tmp/pty96-exit-plain)
(! grep -aF ';exit=' /tmp/pty96-exit-plain)

# TTY configured by path, with TTYReset= off so that only TTYExitStatus= causes the context to be closed
# shellcheck disable=SC2016
script -qec 'systemd-run --quiet --wait -u pty96-exit-path.service -p TTYPath="$(tty)" -p StandardOutput=tty -p TTYExitStatus=yes true' /tmp/pty96-exit-path </dev/null >/dev/null || :
assert_exit_record /tmp/pty96-exit-path pty96-exit-path.service 'exit=success;status=0'

# run0 on a TTY starts its shell via the broker, whose shell units set TTYExitStatus=. SIGHUP is how a
# closed terminal ends a shell, hence an interrupt rather than a crash.
cat >/tmp/pty96-exit-shell-status <<'SHELLEOF'
#!/bin/sh
exit 5
SHELLEOF
cat >/tmp/pty96-exit-shell-hup <<'SHELLEOF'
#!/bin/sh
kill -HUP $$
SHELLEOF
chmod +x /tmp/pty96-exit-shell-status /tmp/pty96-exit-shell-hup

script -qec 'run0 --setenv=SHELL=/tmp/pty96-exit-shell-status' /tmp/pty96-exit-broker-status </dev/null >/dev/null || :
assert_exit_record /tmp/pty96-exit-broker-status 'shell-[^;]*\.service' 'exit=failure;status=5'

script -qec 'run0 --setenv=SHELL=/tmp/pty96-exit-shell-hup' /tmp/pty96-exit-broker-hup </dev/null >/dev/null || :
assert_exit_record /tmp/pty96-exit-broker-hup 'shell-[^;]*\.service' 'exit=interrupt;signal=SIGHUP'

# A forged end record with the ID derived from $INVOCATION_ID must not pass for the real one
cat >/tmp/pty96-exit-forge <<'SHELLEOF'
#!/bin/sh
set -eu
derived="$(systemd-id128 show --value --app-specific=5d63a58d96fd45d0a0f06350fcd89acd "$INVOCATION_ID")"
echo "$derived" >/tmp/pty96-exit-forge-id
printf '\033]3008;end=%s;exit=success;status=0\033\\' "$derived"
exit 3
SHELLEOF
chmod +x /tmp/pty96-exit-forge

run_pty /tmp/pty96-exit-forge-out -u pty96-exit-forge.service -p TTYExitStatus=yes /tmp/pty96-exit-forge
assert_exit_record /tmp/pty96-exit-forge-out pty96-exit-forge.service 'exit=failure;status=3'
FORGED_ID="$(cat /tmp/pty96-exit-forge-id)"
grep -aF "3008;end=$FORGED_ID;exit=success" /tmp/pty96-exit-forge-out
(! grep -aF "3008;start=$FORGED_ID" /tmp/pty96-exit-forge-out)
