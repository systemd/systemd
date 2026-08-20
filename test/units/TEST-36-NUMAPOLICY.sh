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
        # Each dump is guarded so a missing file cannot become the trap's status: set -e is
        # active here, and the exit status this trap reports on would be rewritten by it.
        if [[ -v straceLog && -f "$straceLog" ]]; then cat "$straceLog"; fi
        if [[ -v journalLog && -f "$journalLog" ]]; then cat "$journalLog"; fi
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
    # Save journal's cursor for later navigation
    journalctl --no-pager --cursor-file="$journalCursorFile" -n0 -ocat
}

stopJournalctl() {
    local unit="${1:-init.scope}"
    # Using journalctl --sync should be better than using SIGRTMIN+1, as
    # the --sync wait until the synchronization is complete
    echo "Force journald to write all queued messages"
    journalctl --sync
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
    printf "[Service]\nExecStart=sleep 3600\n" >"$testUnitFile"
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

pid1StartUnitWithJournal() {
    # The capture is closed by the caller, after it has waited for the state it asserts on:
    # systemctl start returns for a simple service as soon as the fork succeeds, so a stop here
    # would close the window before the exec child has reached the NUMA step, and the artifact
    # dumped by at_exit would not contain the lines that explain a failure.
    startJournalctl
    systemctl start "${1:?}"
}

pid1StopUnit() {
    systemctl stop "${1:?}"
}

waitUnitMainExited() {
    # Wait until PID1 has recorded the main process's exit, so ExecMainStatus holds the exec
    # child's own result rather than the signal a later stop would deliver. "Started ..." is
    # logged for a simple service as soon as the fork succeeds, which orders nothing.
    # A failed read prints nothing, and an empty string must keep the loop waiting rather than
    # read as "exited": -P prints 0 for a unit whose main process has not exited yet.
    # shellcheck disable=SC2016 # $1 is expanded by the inner shell, which gets it as an argument
    timeout 30 bash -xeuc 'until code=$(systemctl show "$1" -P ExecMainCode) && [[ -n "$code" && "$code" != 0 ]]; do sleep .5; done' bash "${1:?}"
}

# Start the unit with a journal capture, run the given wait on it, and close the capture on
# both paths, preserving the wait's own exit status (timeout's 124 at the bound).
startUnitWaitJournal() {
    local unit="${1:?}" waitFn="${2:?}"
    local rc=0

    pid1StartUnitWithJournal "$unit"
    "$waitFn" "$unit" || rc=$?
    stopJournalctl "$unit"
    [[ $rc -eq 0 ]] || exit "$rc"
}

waitUnitMainHandoff() {
    # Wait until the exec child has reached the handoff timestamp, which systemd-executor sends
    # right before execve(), after all of exec setup including the NUMA step. A child whose
    # policy is rejected exits at that step instead and never sends it, so the property stays 0
    # and the wait fails at the bound. A failed read prints nothing, and an empty string must
    # keep the loop waiting, same as the 0 the property holds until the handoff arrives.
    # shellcheck disable=SC2016 # $1 is expanded by the inner shell, which gets it as an argument
    timeout 30 bash -xeuc 'until ts=$(systemctl show "$1" -P ExecMainHandoffTimestampMonotonic) && [[ "$ts" =~ ^[1-9] ]]; do sleep .5; done' bash "${1:?}"
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
    # the exec setup that logs the message this subtest greps for. That also means systemd-run
    # itself can fail right here, so the capture is closed on both paths: journal.log still
    # holds the previous subtest's init.scope window, which contains the exact string the grep
    # below looks for.
    rc=0
    systemd-run --service-type=exec -p NUMAPolicy=default -p NUMAMask=0 --unit "$runUnit" sleep 1000 || rc=$?
    stopJournalctl "$runUnit"
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
    startUnitWaitJournal "$testUnit" waitUnitMainExited
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
    startUnitWaitJournal "$testUnit" waitUnitMainExited
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
    # the wait times out with 124, which the helper's exit preserves. A negated grep for the
    # executor's failure line would assert nothing on top: reaching the next line means the
    # handoff arrived, which the NUMA step precedes.
    startUnitWaitJournal "$testUnit" waitUnitMainHandoff
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
    startUnitWaitJournal "$testUnit" waitUnitMainExited
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
    startUnitWaitJournal "$testUnit" waitUnitMainExited
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
