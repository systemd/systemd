#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [[ -n "${ASAN_OPTIONS:-}" ]]; then
    echo "This test does not support running with sanitizers, skipping the test" | tee --append /skipped
    exit 77
fi

# shellcheck disable=SC2317
at_exit() {
    # shellcheck disable=SC2181
    if [[ $? -ne 0 ]]; then
        # We're exiting with a non-zero EC, let's dump test artifacts
        # for easier debugging
        # Each dump is guarded so neither a missing file nor a failed read can become the
        # trap's status: set -e is active here, and the exit status this trap reports on
        # would be rewritten by it.
        if [[ -v straceLog && -f "$straceLog" ]]; then cat "$straceLog" || :; fi
        if [[ -v journalLog && -f "$journalLog" ]]; then cat "$journalLog" || :; fi
    fi
}

trap at_exit EXIT

# Log files
straceLog='strace.log'
journalLog='journal.log'

# Systemd config files
testUnit='numa-test.service'
testUnitFile="/run/systemd/system/$testUnit"
testUnitNUMAConf="$testUnitFile.d/numa.conf"

# Sleep constants (we should probably figure out something better but nothing comes to mind)
sleepAfterStart=3

# Journal cursor for easier navigation
journalCursorFile="journalCursorFile"

startStrace() {
    # Mirror of the $straceLog clear in startUnitWaitJournal: at_exit dumps both artifacts,
    # and this path never writes the journal window.
    : >"$journalLog"
    coproc strace -qq -p 1 -o "$straceLog" -e set_mempolicy -s 1024 ${1:+"$1"}
    # Wait for strace to properly "initialize", i.e. until PID 1 has the TracerPid
    # field set to the current strace's PID
    until awk -v spid="$COPROC_PID" '/^TracerPid:/ {exit !($2 == spid);}' /proc/1/status; do sleep 0.1; done
}

stopStrace() {
    [[ -v COPROC_PID ]] || return

    local PID=$COPROC_PID
    kill -s TERM "$PID"
    # Make sure the strace process is indeed dead
    while kill -0 "$PID" 2>/dev/null; do sleep 0.1; done
}

startJournalctl() {
    : >"$journalCursorFile"
    # Truncate here too: a failed --sync returns before the windowed read, and a stale
    # window would then be dumped as this subtest's.
    : >"$journalLog"
    # Save journal's cursor for later navigation
    journalctl --no-pager --cursor-file="$journalCursorFile" -n0 -ocat
}

stopJournalctl() {
    local unit="${1:-init.scope}"
    # Using journalctl --sync should be better than using SIGRTMIN+1, as
    # the --sync wait until the synchronization is complete
    echo "Force journald to write all queued messages"
    # Callers that capture this function's status disable errexit inside it, so a failed
    # sync must return here rather than fall through to the windowed read, which would
    # rewrite the log and hide the fault behind its own success.
    journalctl --sync || return
    journalctl -u "$unit" --cursor-file="$journalCursorFile" >"$journalLog"
}

checkNUMA() {
    # NUMA enabled system should have at least NUMA node0
    test -e /sys/devices/system/node/node0
}

writePID1NUMAPolicy() {
    cat >"$confDir/numa.conf" <<EOF
[Manager]
NUMAPolicy=${1:?}
NUMAMask=${2:-""}
EOF
}

writeTestUnit() {
    mkdir -p "$testUnitFile.d/"
    # Several subtests deliberately fail this unit with EXIT_NUMA_POLICY and nothing resets
    # it, so PID1 retains its start counter across them; at the default 5-in-10s that is
    # reachable once the waits replaced the fixed sleeps.
    printf "[Unit]\nStartLimitIntervalSec=0\n[Service]\nExecStart=sleep 3600\n" >"$testUnitFile"
}

writeTestUnitNUMAPolicy() {
    cat >"$testUnitNUMAConf" <<EOF
[Service]
NUMAPolicy=${1:?}
NUMAMask=${2:-""}
EOF
    systemctl daemon-reload
}

pid1ReloadWithStrace() {
    startStrace
    systemctl daemon-reload
    sleep $sleepAfterStart
    stopStrace
}

pid1ReloadWithJournal() {
    startJournalctl
    systemctl daemon-reload
    stopJournalctl
}

pid1StartUnitWithStrace() {
    startStrace '-f'
    systemctl start "${1:?}"
    sleep $sleepAfterStart
    stopStrace
}

pid1StopUnit() {
    systemctl stop "${1:?}"
}

# A main-process property read that must never abort the caller: a read can fail or print
# nothing, and either must read as "not terminal", since both properties below print 0 until
# they go terminal.
unitPropertyTerminal() {
    local unit="${1:?}" prop="${2:?}"
    local value

    value=$(systemctl show "$unit" -P "$prop") || value=''
    [[ -n "$value" && "$value" != 0 ]]
}

# Poll for the terminal state of the unit's main process: "exited" waits for ExecMainCode,
# which is when PID1 has recorded the child's own result rather than the signal a later stop
# would deliver, and "handoff" waits for ExecMainHandoffTimestampMonotonic, which
# systemd-executor sends right before execve(), after all of exec setup including the NUMA
# step. "Started ..." is logged for a simple service as soon as the fork succeeds, which
# orders nothing. Every caller expects exactly one of the two: a rejected policy exits at
# the NUMA step, which precedes the handoff, and an accepted one hands off and keeps
# running. So observing the complementary property is the regression the subtest exists to
# catch, and fails right away with a diagnostic naming ExecMainStatus instead of polling to
# the 30 second bound; the awaited property is re-read first so a child that raced in
# between still counts. Returns 124 at the bound.
waitUnitMain() {
    local unit="${1:?}" direction="${2:?}"
    local awaited complement message deadline

    case "$direction" in
        exited)  awaited=ExecMainCode
                 complement=ExecMainHandoffTimestampMonotonic
                 message='reached the exec handoff instead of dying at the NUMA step' ;;
        handoff) awaited=ExecMainHandoffTimestampMonotonic
                 complement=ExecMainCode
                 message='main process exited before the exec handoff' ;;
        *)       echo >&2 "unknown wait direction $direction"; return 1 ;;
    esac

    deadline=$((SECONDS + 30))
    until unitPropertyTerminal "$unit" "$awaited"; do
        if unitPropertyTerminal "$unit" "$complement"; then
            unitPropertyTerminal "$unit" "$awaited" && return 0
            echo >&2 "$unit $message (ExecMainStatus=$(systemctl show "$unit" -P ExecMainStatus))"
            return 1
        fi
        [[ $SECONDS -lt $deadline ]] || return 124
        sleep .5
    done
    return 0
}

# Start the unit with a journal capture, run the given wait on it, and close the capture on
# every path, a failed start included, so the at_exit dump always shows this subtest's
# window. The capture closes only after the wait, since systemctl start returns for a
# simple service as soon as the fork succeeds, before the exec child has reached the NUMA
# step whose lines explain a failure. A failing start or wait keeps its own status (124 at
# the wait's bound): the close runs with its status captured, so it cannot rewrite one.
startUnitWaitJournal() {
    local unit="${1:?}" direction="${2:?}"
    local rc=0 capRc=0

    # at_exit dumps $straceLog whenever it exists; this helper never writes it, so clear it
    # rather than show a neighbouring subtest's set_mempolicy as this failure's evidence.
    : >"$straceLog"
    # This window is only dumped by at_exit, never read at this helper's call sites, so
    # neither end of the capture may pre-empt the caller's assertion. Close only a window
    # that opened: without a cursor the read falls back to unfiltered history.
    startJournalctl || capRc=$?
    systemctl start "$unit" || rc=$?
    if [[ $rc -eq 0 ]]; then
        waitUnitMain "$unit" "$direction" || rc=$?
    fi
    if [[ $capRc -eq 0 ]]; then
        stopJournalctl "$unit" || capRc=$?
    fi
    [[ $capRc -eq 0 ]] || echo >&2 "$unit journal capture failed ($capRc)"
    return "$rc"
}

systemctlCheckNUMAProperties() {
    local UNIT_NAME="${1:?}"
    local NUMA_POLICY="${2:?}"
    local NUMA_MASK="${3:-""}"
    local LOGFILE

    LOGFILE="$(mktemp)"

    systemctl show -p NUMAPolicy "$UNIT_NAME" >"$LOGFILE"
    grep "NUMAPolicy=$NUMA_POLICY" "$LOGFILE"

    : >"$LOGFILE"

    if [ -n "$NUMA_MASK" ]; then
        systemctl show -p NUMAMask "$UNIT_NAME" >"$LOGFILE"
        grep "NUMAMask=$NUMA_MASK" "$LOGFILE"
    fi
}

writeTestUnit

# Create systemd config drop-in directory
confDir="/run/systemd/system.conf.d/"
mkdir -p "$confDir"

if ! checkNUMA; then
    echo >&2 "NUMA is not supported on this machine, switching to a simple sanity check"

    echo "PID1 NUMAPolicy=default && NUMAMask=0 check without NUMA support"
    writePID1NUMAPolicy "default" "0"
    startJournalctl
    systemctl daemon-reload
    stopJournalctl
    grep "NUMA support not available, ignoring" "$journalLog"

    echo "systemd-run NUMAPolicy=default && NUMAMask=0 check without NUMA support"
    runUnit='numa-systemd-run-test.service'
    startJournalctl
    # Type=exec holds systemd-run until the service binary has been executed, which is after
    # the exec setup that logs the message this subtest greps for. systemd-run itself can fail
    # right here, and the capture is closed before that is checked: leaving it open would leave
    # journal.log holding the previous subtest's init.scope window, which contains the exact
    # string the grep below looks for and would turn a failure here into a false pass.
    rc=0
    stopRc=0
    systemd-run --service-type=exec -p NUMAPolicy=default -p NUMAMask=0 --unit "$runUnit" sleep 1000 || rc=$?
    stopJournalctl "$runUnit" || stopRc=$?
    [[ $rc -ne 0 ]] || rc=$stopRc
    [[ $rc -eq 0 ]] || exit "$rc"
    grep "NUMA support not available, ignoring" "$journalLog"
    pid1StopUnit "$runUnit"

else
    echo "PID1 NUMAPolicy support - Default policy w/o mask"
    writePID1NUMAPolicy "default"
    pid1ReloadWithStrace
    # Kernel requires that nodemask argument is set to NULL when setting default policy
    grep "set_mempolicy(MPOL_DEFAULT, NULL" "$straceLog"

    echo "PID1 NUMAPolicy support - Default policy w/ mask"
    writePID1NUMAPolicy "default" "0"
    pid1ReloadWithStrace
    grep "set_mempolicy(MPOL_DEFAULT, NULL" "$straceLog"

    echo "PID1 NUMAPolicy support - Bind policy w/o mask"
    writePID1NUMAPolicy "bind"
    pid1ReloadWithJournal
    grep "Failed to set NUMA memory policy, ignoring: Invalid argument" "$journalLog"

    echo "PID1 NUMAPolicy support - Bind policy w/ mask"
    writePID1NUMAPolicy "bind" "0"
    pid1ReloadWithStrace
    grep -P "set_mempolicy\(MPOL_BIND, \[0x0*1\]" "$straceLog"

    echo "PID1 NUMAPolicy support - Interleave policy w/o mask"
    writePID1NUMAPolicy "interleave"
    pid1ReloadWithJournal
    grep "Failed to set NUMA memory policy, ignoring: Invalid argument" "$journalLog"

    echo "PID1 NUMAPolicy support - Interleave policy w/ mask"
    writePID1NUMAPolicy "interleave" "0"
    pid1ReloadWithStrace
    grep -P "set_mempolicy\(MPOL_INTERLEAVE, \[0x0*1\]" "$straceLog"

    echo "PID1 NUMAPolicy support - Preferred policy w/o mask"
    writePID1NUMAPolicy "preferred"
    pid1ReloadWithJournal
    # Preferred policy with empty node mask is actually allowed and should reset allocation policy to default
    grep "Failed to set NUMA memory policy, ignoring: Invalid argument" "$journalLog" && { echo >&2 "unexpected pass"; exit 1; }

    echo "PID1 NUMAPolicy support - Preferred policy w/ mask"
    writePID1NUMAPolicy "preferred" "0"
    pid1ReloadWithStrace
    grep -P "set_mempolicy\(MPOL_PREFERRED, \[0x0*1\]" "$straceLog"

    echo "PID1 NUMAPolicy support - Local policy w/o mask"
    writePID1NUMAPolicy "local"
    pid1ReloadWithStrace
    # Kernel requires that nodemask argument is set to NULL when setting default policy
    # The unpatched versions of strace don't recognize the MPOL_LOCAL constant and
    # return a numerical constant instead (with a comment):
    #   set_mempolicy(0x4 /* MPOL_??? */, NULL, 0) = 0
    # Let's cover this scenario as well
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" "$straceLog"

    echo "PID1 NUMAPolicy support - Local policy w/ mask"
    writePID1NUMAPolicy "local" "0"
    pid1ReloadWithStrace
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" "$straceLog"

    echo "PID1 NUMAPolicy support - Preferred-many policy w/o mask"
    writePID1NUMAPolicy "preferred-many"
    pid1ReloadWithJournal
    grep "Failed to set NUMA memory policy, ignoring: Invalid argument" "$journalLog"

    echo "PID1 NUMAPolicy support - Preferred-many policy w/ mask"
    writePID1NUMAPolicy "preferred-many" "0"
    pid1ReloadWithStrace
    grep -E "set_mempolicy\((MPOL_PREFERRED_MANY|0x5 [^,]*), \[0x0*1\]" "$straceLog"

    echo "PID1 NUMAPolicy support - Weighted-interleave policy w/o mask"
    writePID1NUMAPolicy "weighted-interleave"
    pid1ReloadWithJournal
    grep "Failed to set NUMA memory policy, ignoring: Invalid argument" "$journalLog"

    echo "PID1 NUMAPolicy support - Weighted-interleave policy w/ mask"
    writePID1NUMAPolicy "weighted-interleave" "0"
    pid1ReloadWithStrace
    grep -E "set_mempolicy\((MPOL_WEIGHTED_INTERLEAVE|0x6 [^,]*), \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Default policy w/o mask"
    writeTestUnitNUMAPolicy "default"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "default"
    pid1StopUnit "$testUnit"
    grep "set_mempolicy(MPOL_DEFAULT, NULL" "$straceLog"

    echo "Unit file NUMAPolicy support - Default policy w/ mask"
    writeTestUnitNUMAPolicy "default" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "default" "0"
    pid1StopUnit $testUnit
    # Mask must be ignored
    grep "set_mempolicy(MPOL_DEFAULT, NULL" "$straceLog"

    echo "Unit file NUMAPolicy support - Bind policy w/o mask"
    writeTestUnitNUMAPolicy "bind"
    startUnitWaitJournal "$testUnit" exited
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]
    pid1StopUnit "$testUnit"

    echo "Unit file NUMAPolicy support - Bind policy w/ mask"
    writeTestUnitNUMAPolicy "bind" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "bind" "0"
    pid1StopUnit "$testUnit"
    grep -P "set_mempolicy\(MPOL_BIND, \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Interleave policy w/o mask"
    writeTestUnitNUMAPolicy "interleave"
    startUnitWaitJournal "$testUnit" exited
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]
    pid1StopUnit "$testUnit"

    echo "Unit file NUMAPolicy support - Interleave policy w/ mask"
    writeTestUnitNUMAPolicy "interleave" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "interleave" "0"
    pid1StopUnit "$testUnit"
    grep -P "set_mempolicy\(MPOL_INTERLEAVE, \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Preferred policy w/o mask"
    writeTestUnitNUMAPolicy "preferred"
    # The handoff wait is the live check here: a preferred policy wrongly rejected for its empty
    # mask dies at the NUMA step with EXIT_NUMA_POLICY, the handoff timestamp never arrives, and
    # the wait fails at once with a diagnostic naming the child's ExecMainStatus. A negated grep for
    # the executor's failure line would assert nothing on top: reaching the next line means the
    # handoff arrived, which the NUMA step precedes.
    startUnitWaitJournal "$testUnit" handoff
    systemctlCheckNUMAProperties "$testUnit" "preferred"
    pid1StopUnit "$testUnit"

    echo "Unit file NUMAPolicy support - Preferred policy w/ mask"
    writeTestUnitNUMAPolicy "preferred" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "preferred" "0"
    pid1StopUnit "$testUnit"
    grep -P "set_mempolicy\(MPOL_PREFERRED, \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Local policy w/o mask"
    writeTestUnitNUMAPolicy "local"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "local"
    pid1StopUnit "$testUnit"
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" "$straceLog"

    echo "Unit file NUMAPolicy support - Local policy w/ mask"
    writeTestUnitNUMAPolicy "local" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "local" "0"
    pid1StopUnit "$testUnit"
    # Mask must be ignored
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" "$straceLog"

    echo "Unit file NUMAPolicy support - Preferred-many policy w/o mask"
    writeTestUnitNUMAPolicy "preferred-many"
    startUnitWaitJournal "$testUnit" exited
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]
    pid1StopUnit "$testUnit"

    echo "Unit file NUMAPolicy support - Preferred-many policy w/ mask"
    writeTestUnitNUMAPolicy "preferred-many" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "preferred-many" "0"
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "{\"name\":\"$testUnit\"}" | jq -e '.context.Exec.NUMAPolicy == "preferred_many"'
    pid1StopUnit "$testUnit"
    grep -E "set_mempolicy\((MPOL_PREFERRED_MANY|0x5 [^,]*), \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Weighted-interleave policy w/o mask"
    writeTestUnitNUMAPolicy "weighted-interleave"
    startUnitWaitJournal "$testUnit" exited
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]
    pid1StopUnit "$testUnit"

    echo "Unit file NUMAPolicy support - Weighted-interleave policy w/ mask"
    writeTestUnitNUMAPolicy "weighted-interleave" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "weighted-interleave" "0"
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "{\"name\":\"$testUnit\"}" | jq -e '.context.Exec.NUMAPolicy == "weighted_interleave"'
    pid1StopUnit "$testUnit"
    grep -E "set_mempolicy\((MPOL_WEIGHTED_INTERLEAVE|0x6 [^,]*), \[0x0*1\]" "$straceLog"

    echo "Unit file CPUAffinity=NUMA support"
    writeTestUnitNUMAPolicy "bind" "0"
    echo "CPUAffinity=numa" >>"$testUnitNUMAConf"
    systemctl daemon-reload
    systemctl start "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "bind" "0"
    cpulist="$(cat /sys/devices/system/node/node0/cpulist)"
    affinity_systemd="$(systemctl show --value -p CPUAffinity "$testUnit")"
    [ "$cpulist" = "$affinity_systemd" ]
    pid1StopUnit "$testUnit"

    echo "systemd-run NUMAPolicy support"
    runUnit='numa-systemd-run-test.service'

    systemd-run -p NUMAPolicy=default --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "default"
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=default -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "default" ""
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=bind -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "bind" "0"
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=interleave -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "interleave" "0"
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=preferred -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "preferred" "0"
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=local --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "local"
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=local -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "local" ""
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=local -p NUMAMask=0 -p CPUAffinity=numa --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "local" ""
    systemctl cat "$runUnit" | grep 'CPUAffinity=numa' >/dev/null
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=preferred-many -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "preferred-many" "0"
    pid1StopUnit "$runUnit"

    systemd-run -p NUMAPolicy=weighted-interleave -p NUMAMask=0 --unit "$runUnit" sleep 1000
    systemctlCheckNUMAProperties "$runUnit" "weighted-interleave" "0"
    pid1StopUnit "$runUnit"
fi

# Cleanup
rm -rf "$confDir"
systemctl daemon-reload

touch /testok
