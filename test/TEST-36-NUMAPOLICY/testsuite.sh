#!/bin/bash
set -ex
set -o pipefail

at_exit() {
    if [ $? -ne 0 ]; then
        # We're exiting with a non-zero EC, let's dump test artifacts
        # for easier debugging
        [ -f "$straceLog" ] && cat "$straceLog"
        [ -f "$journalLog" ] && cat "$journalLog"
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
testUnitFile="/etc/systemd/system/$testUnit"
testUnitNUMAConf="$testUnitFile.d/numa.conf"

# Sleep constants (we should probably figure out something better but nothing comes to mind)
journalSleep=5
sleepAfterStart=1

# Journal cursor for easier navigation
journalCursorFile="jounalCursorFile"

startStrace() {
    coproc strace -qq -p 1 -o $straceLog -e set_mempolicy -s 1024 $1
    # Wait for strace to properly "initialize"
    sleep $sleepAfterStart
}

stopStrace() {
    kill -s TERM $COPROC_PID
    # Make sure the strace process is indeed dead
    while kill -0 $COPROC_PID 2>/dev/null; do sleep 0.1; done
}

startJournalctl() {
    # Save journal's cursor for later navigation
    journalctl --no-pager --cursor-file="$journalCursorFile" -n0 -ocat
}

stopJournalctl() {
    local unit="${1:-init.scope}"
    # Using journalctl --sync should be better than using SIGRTMIN+1, as
    # the --sync wait until the synchronization is complete
    echo "Force journald to write all queued messages"
    journalctl --sync
    journalctl -u $unit --cursor-file="$journalCursorFile" > "$journalLog"
}

checkNUMA() {
    # NUMA enabled system should have at least NUMA node0
    test -e /sys/devices/system/node/node0
}

writePID1NUMAPolicy() {
    echo [Manager] > $confDir/numa.conf
    echo NUMAPolicy=$1 >> $confDir/numa.conf
    echo NUMAMask=$2>> $confDir/numa.conf
}

writeTestUnit() {
    echo [Service] > $testUnitFile
    echo ExecStart=/bin/sleep 3600 >> $testUnitFile
    mkdir -p $testUnitFile.d/
}

writeTestUnitNUMAPolicy() {
    echo [Service] > $testUnitNUMAConf
    echo NUMAPolicy=$1 >> $testUnitNUMAConf
    echo NUMAMask=$2>> $testUnitNUMAConf
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
    systemctl start $1
    sleep $sleepAfterStart
    stopStrace
}

pid1StartUnitWithJournal() {
    startJournalctl
    systemctl start $1
    sleep $sleepAfterStart
    stopJournalctl
}

pid1StopUnit() {
    systemctl stop $1
}

systemctlCheckNUMAProperties() {
    local LOGFILE="$(mktemp)"
    systemctl show -p NUMAPolicy $1 > "$LOGFILE"
    grep "NUMAPolicy=$2" "$LOGFILE"

    > "$LOGFILE"

    if [ -n $3 ]; then
        systemctl show -p NUMAMask $1 > "$LOGFILE"
        grep "NUMAMask=$3" "$LOGFILE"
    fi
}

writeTestUnit

# Create systemd config drop-in directory
confDir="/etc/systemd/system.conf.d/"
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
    systemd-run -p NUMAPolicy=default -p NUMAMask=0 --unit $runUnit sleep 1000
    sleep $sleepAfterStart
    pid1StopUnit $runUnit
    stopJournalctl $runUnit
    grep "NUMA support not available, ignoring" "$journalLog"

else
    echo "PID1 NUMAPolicy support - Default policy w/o mask"
    writePID1NUMAPolicy "default"
    pid1ReloadWithStrace
    # Kernel requires that nodemask argument is set to NULL when setting default policy
    grep "set_mempolicy(MPOL_DEFAULT, NULL" $straceLog

    echo "PID1 NUMAPolicy support - Default policy w/ mask"
    writePID1NUMAPolicy "default" "0"
    pid1ReloadWithStrace
    grep "set_mempolicy(MPOL_DEFAULT, NULL" $straceLog

    echo "PID1 NUMAPolicy support - Bind policy w/o mask"
    writePID1NUMAPolicy "bind"
    pid1ReloadWithJournal
    grep "Failed to set NUMA memory policy: Invalid argument" $journalLog

    echo "PID1 NUMAPolicy support - Bind policy w/ mask"
    writePID1NUMAPolicy "bind" "0"
    pid1ReloadWithStrace
    grep -P "set_mempolicy\(MPOL_BIND, \[0x0*1\]" $straceLog

    echo "PID1 NUMAPolicy support - Interleave policy w/o mask"
    writePID1NUMAPolicy "interleave"
    pid1ReloadWithJournal
    grep "Failed to set NUMA memory policy: Invalid argument" $journalLog

    echo "PID1 NUMAPolicy support - Interleave policy w/ mask"
    writePID1NUMAPolicy "interleave" "0"
    pid1ReloadWithStrace
    grep -P "set_mempolicy\(MPOL_INTERLEAVE, \[0x0*1\]" $straceLog

    echo "PID1 NUMAPolicy support - Preferred policy w/o mask"
    writePID1NUMAPolicy "preferred"
    pid1ReloadWithJournal
    # Preferred policy with empty node mask is actually allowed and should reset allocation policy to default
    ! grep "Failed to set NUMA memory policy: Invalid argument" $journalLog

    echo "PID1 NUMAPolicy support - Preferred policy w/ mask"
    writePID1NUMAPolicy "preferred" "0"
    pid1ReloadWithStrace
    grep -P "set_mempolicy\(MPOL_PREFERRED, \[0x0*1\]" $straceLog

    echo "PID1 NUMAPolicy support - Local policy w/o mask"
    writePID1NUMAPolicy "local"
    pid1ReloadWithStrace
    # Kernel requires that nodemask argument is set to NULL when setting default policy
    # The unpatched versions of strace don't recognize the MPOL_LOCAL constant and
    # return a numerical constant instead (with a comment):
    #   set_mempolicy(0x4 /* MPOL_??? */, NULL, 0) = 0
    # Let's cover this scenario as well
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" $straceLog

    echo "PID1 NUMAPolicy support - Local policy w/ mask"
    writePID1NUMAPolicy "local" "0"
    pid1ReloadWithStrace
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" $straceLog

    echo "Unit file NUMAPolicy support - Default policy w/o mask"
    writeTestUnitNUMAPolicy "default"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "default"
    pid1StopUnit $testUnit
    grep "set_mempolicy(MPOL_DEFAULT, NULL" $straceLog

    echo "Unit file NUMAPolicy support - Default policy w/ mask"
    writeTestUnitNUMAPolicy "default" "0"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "default" "0"
    pid1StopUnit $testUnit
    # Maks must be ignored
    grep "set_mempolicy(MPOL_DEFAULT, NULL" $straceLog

    echo "Unit file NUMAPolicy support - Bind policy w/o mask"
    writeTestUnitNUMAPolicy "bind"
    pid1StartUnitWithJournal $testUnit
    pid1StopUnit $testUnit
    grep "numa-test.service: Main process exited, code=exited, status=242/NUMA" $journalLog

    echo "Unit file NUMAPolicy support - Bind policy w/ mask"
    writeTestUnitNUMAPolicy "bind" "0"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "bind" "0"
    pid1StopUnit $testUnit
    grep -P "set_mempolicy\(MPOL_BIND, \[0x0*1\]" $straceLog

    echo "Unit file NUMAPolicy support - Interleave policy w/o mask"
    writeTestUnitNUMAPolicy "interleave"
    pid1StartUnitWithStrace $testUnit
    pid1StopUnit $testUnit
    grep "numa-test.service: Main process exited, code=exited, status=242/NUMA" $journalLog

    echo "Unit file NUMAPolicy support - Interleave policy w/ mask"
    writeTestUnitNUMAPolicy "interleave" "0"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "interleave" "0"
    pid1StopUnit $testUnit
    grep -P "set_mempolicy\(MPOL_INTERLEAVE, \[0x0*1\]" $straceLog

    echo "Unit file NUMAPolicy support - Preferred policy w/o mask"
    writeTestUnitNUMAPolicy "preferred"
    pid1StartUnitWithJournal $testUnit
    systemctlCheckNUMAProperties $testUnit "preferred"
    pid1StopUnit $testUnit
    ! grep "numa-test.service: Main process exited, code=exited, status=242/NUMA" $journalLog

    echo "Unit file NUMAPolicy support - Preferred policy w/ mask"
    writeTestUnitNUMAPolicy "preferred" "0"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "preferred" "0"
    pid1StopUnit $testUnit
    grep -P "set_mempolicy\(MPOL_PREFERRED, \[0x0*1\]" $straceLog

    echo "Unit file NUMAPolicy support - Local policy w/o mask"
    writeTestUnitNUMAPolicy "local"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "local"
    pid1StopUnit $testUnit
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" $straceLog

    echo "Unit file NUMAPolicy support - Local policy w/ mask"
    writeTestUnitNUMAPolicy "local" "0"
    pid1StartUnitWithStrace $testUnit
    systemctlCheckNUMAProperties $testUnit "local" "0"
    pid1StopUnit $testUnit
    # Maks must be ignored
    grep -E "set_mempolicy\((MPOL_LOCAL|0x4 [^,]*), NULL" $straceLog

    echo "systemd-run NUMAPolicy support"
    runUnit='numa-systemd-run-test.service'

    systemd-run -p NUMAPolicy=default --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "default"
    pid1StopUnit $runUnit

    systemd-run -p NUMAPolicy=default -p NUMAMask=0 --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "default" ""
    pid1StopUnit $runUnit

    systemd-run -p NUMAPolicy=bind -p NUMAMask=0 --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "bind" "0"
    pid1StopUnit $runUnit

    systemd-run -p NUMAPolicy=interleave -p NUMAMask=0 --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "interleave" "0"
    pid1StopUnit $runUnit

    systemd-run -p NUMAPolicy=preferred -p NUMAMask=0 --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "preferred" "0"
    pid1StopUnit $runUnit

    systemd-run -p NUMAPolicy=local --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "local"
    pid1StopUnit $runUnit

    systemd-run -p NUMAPolicy=local -p NUMAMask=0 --unit $runUnit sleep 1000
    systemctlCheckNUMAProperties $runUnit "local" ""
    pid1StopUnit $runUnit
fi

# Cleanup
rm -rf $testDir
rm -rf $confDir
systemctl daemon-reload

systemd-analyze log-level info

echo OK > /testok

exit 0
