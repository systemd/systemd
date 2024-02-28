#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck disable=SC2317
at_exit() {
    # shellcheck disable=SC2181
    if [[ $? -ne 0 ]]; then
        # We're exiting with a non-zero EC, let's dump test artifacts
        # for easier debugging
        [[ -v straceLog && -f "$straceLog" ]] && cat "$straceLog"
        [[ -v journalLog && -f "$journalLog" ]] && cat "$journalLog"
    fi
}

trap at_exit EXIT

systemd-analyze log-level debug
systemd-analyze log-target journal

# Log files
straceLog='strace.log'
journalLog='journal.log'

# Systemd config files
testUnit='numa-test.service'
testUnitFile="/run/systemd/system/$testUnit"
testUnitNUMAConf="$testUnitFile.d/numa.conf"

# Sleep constants (we should probably figure out something better but nothing comes to mind)
sleepAfterStart=1

# Journal cursor for easier navigation
journalCursorFile="jounalCursorFile"

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
    startJournalctl
    systemctl start "${1:?}"
    sleep $sleepAfterStart
    stopJournalctl
}

pid1StopUnit() {
    systemctl stop "${1:?}"
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
    systemd-run -p NUMAPolicy=default -p NUMAMask=0 --unit "$runUnit" sleep 1000
    sleep $sleepAfterStart
    pid1StopUnit "$runUnit"
    stopJournalctl "$runUnit"
    grep "NUMA support not available, ignoring" "$journalLog"

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
    pid1StartUnitWithJournal "$testUnit"
    pid1StopUnit "$testUnit"
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]

    echo "Unit file NUMAPolicy support - Bind policy w/ mask"
    writeTestUnitNUMAPolicy "bind" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "bind" "0"
    pid1StopUnit "$testUnit"
    grep -P "set_mempolicy\(MPOL_BIND, \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Interleave policy w/o mask"
    writeTestUnitNUMAPolicy "interleave"
    pid1StartUnitWithStrace "$testUnit"
    pid1StopUnit "$testUnit"
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]

    echo "Unit file NUMAPolicy support - Interleave policy w/ mask"
    writeTestUnitNUMAPolicy "interleave" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "interleave" "0"
    pid1StopUnit "$testUnit"
    grep -P "set_mempolicy\(MPOL_INTERLEAVE, \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Preferred policy w/o mask"
    writeTestUnitNUMAPolicy "preferred"
    pid1StartUnitWithJournal "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "preferred"
    pid1StopUnit "$testUnit"
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]] && { echo >&2 "unexpected pass"; exit 1; }

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
    systemctl cat "$runUnit" | grep -q 'CPUAffinity=numa'
    pid1StopUnit "$runUnit"
fi

# Cleanup
rm -rf "$confDir"
systemctl daemon-reload

systemd-analyze log-level info

touch /testok
