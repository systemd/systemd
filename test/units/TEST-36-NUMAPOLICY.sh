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
        [[ -v straceLog && -f "$straceLog" ]] && cat "$straceLog"
        [[ -v journalLog && -f "$journalLog" ]] && cat "$journalLog"
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

# Sleep constant for the strace paths, which have no completion marker to wait for. The journal
# paths wait for a marker message instead (see stopJournalctl).
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
    # Save journal's cursor for later navigation. journalctl can transiently open no journal
    # file at all and still exit successfully, so retry until this attempt wrote a cursor,
    # starting each attempt from no file, so a file left by an earlier save cannot satisfy
    # the check or be read as the starting position.
    # shellcheck disable=SC2016 # $1 is expanded by the inner shell, which gets it as an argument
    timeout 30 bash -xec 'until rm -f "$1" && journalctl --sync && journalctl -q -n0 --cursor-file="$1" && test -s "$1"; do sleep 1; done' bash "$journalCursorFile"
}

stopJournalctl() {
    local unit="${1:-init.scope}" marker="${2:?}" cursor

    # Wait until the journal window opened by startJournalctl contains a message the traced
    # operation unconditionally logs. A window that raced the journal comes back empty, which
    # a positive grep reports as a test failure and a negative grep passes vacuously; a window
    # that holds the marker is proven to span the operation. Pass the cursor by value, because
    # a read rewrites --cursor-file even when it matches nothing, which would move a later
    # attempt past the messages it is waiting for.
    cursor="$(cat "$journalCursorFile")"
    test -n "$cursor"
    # shellcheck disable=SC2016 # $1..$3 are expanded by the inner shell, which gets them as arguments
    timeout 30 bash -xec 'until journalctl --sync && journalctl -q -u "$1" --after-cursor="$2" --grep "$3" >/dev/null; do sleep 1; done' bash "$unit" "$cursor" "$marker"

    journalctl -u "$unit" --after-cursor="$cursor" >"$journalLog"
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
    # PID1 logs this once every reload completes, and it applies the NUMA policy before that.
    stopJournalctl init.scope "Reloading finished in"
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
    # PID1 logs "Started ..." to the unit when the fork succeeds. The callers read unit
    # properties rather than this window, so the marker only has to prove the window is live.
    stopJournalctl "${1:?}" "Started "
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
    stopJournalctl init.scope "Reloading finished in"
    grep "NUMA support not available, ignoring" "$journalLog"

    echo "systemd-run NUMAPolicy=default && NUMAMask=0 check without NUMA support"
    runUnit='numa-systemd-run-test.service'
    startJournalctl
    # Type=exec holds systemd-run until the service binary has been executed, which is after
    # the exec setup that logs the message above. The stop then follows the message, so the
    # "Stopped" line proves the window covers both.
    systemd-run --service-type=exec -p NUMAPolicy=default -p NUMAMask=0 --unit "$runUnit" sleep 1000
    pid1StopUnit "$runUnit"
    stopJournalctl "$runUnit" "Stopped "
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

    echo "Unit file NUMAPolicy support - Preferred-many policy w/o mask"
    writeTestUnitNUMAPolicy "preferred-many"
    pid1StartUnitWithStrace "$testUnit"
    pid1StopUnit "$testUnit"
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]

    echo "Unit file NUMAPolicy support - Preferred-many policy w/ mask"
    writeTestUnitNUMAPolicy "preferred-many" "0"
    pid1StartUnitWithStrace "$testUnit"
    systemctlCheckNUMAProperties "$testUnit" "preferred-many" "0"
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "{\"name\":\"$testUnit\"}" | jq -e '.context.Exec.NUMAPolicy == "preferred_many"'
    pid1StopUnit "$testUnit"
    grep -E "set_mempolicy\((MPOL_PREFERRED_MANY|0x5 [^,]*), \[0x0*1\]" "$straceLog"

    echo "Unit file NUMAPolicy support - Weighted-interleave policy w/o mask"
    writeTestUnitNUMAPolicy "weighted-interleave"
    pid1StartUnitWithStrace "$testUnit"
    pid1StopUnit "$testUnit"
    [[ $(systemctl show "$testUnit" -P ExecMainStatus) == "242" ]]

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
