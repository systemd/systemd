#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [[ ! -x /usr/lib/systemd/systemd-rtwatchd ]]; then
    echo "systemd-rtwatchd is not installed, skipping the test"
    exit 0
fi

PID=""
PID_NO_RTTIME=""
WATCH_PID=""
WATCH_LOG="$(mktemp)"

at_exit() {
    set +e
    [[ -n "$PID" ]] && kill "$PID"
    [[ -n "$PID_NO_RTTIME" ]] && kill "$PID_NO_RTTIME"
    [[ -n "$WATCH_PID" ]] && kill "$WATCH_PID"
    rm -f "$WATCH_LOG"
    rm -rf /run/systemd/rtwatchd.conf.d /run/systemd/system/systemd-rtwatchd.service.d
    systemctl daemon-reload
    systemctl stop systemd-rtwatchd.service
}

trap at_exit EXIT

assert_policy() {
    local pid="${1:?}" policy="${2:?}"

    chrt -p "$pid"
    chrt -p "$pid" | grep "scheduling policy: $policy\$" >/dev/null
}

assert_priority() {
    local pid="${1:?}" priority="${2:?}"

    chrt -p "$pid" | grep "scheduling priority: $priority\$" >/dev/null
}

assert_nice() {
    local pid="${1:?}" nice="${2:?}"

    [[ "$(ps -o ni= -p "$pid" | tr -d ' ')" == "$nice" ]]
}

restart_rtwatchd() {
    # We restart the service a couple of times in quick succession, hence make sure we don't hit the start
    # rate limit (which would also put the socket unit into failed state)
    systemctl reset-failed systemd-rtwatchd.service systemd-rtwatchd.socket
    systemctl start systemd-rtwatchd.socket
    systemctl restart systemd-rtwatchd.service
}

systemd-rtwatch --help
systemd-rtwatch --version
systemd-rtwatch --introspect-cli | jq -e '.commands[0].id == "systemd-rtwatch"'

# Command line parsing of the client tool, none of this needs to talk to the service
(! systemd-rtwatch frobnicate) |& grep "Unknown command verb 'frobnicate'" >/dev/null
(! systemd-rtwatch status extra) |& grep "Too many arguments" >/dev/null
(! systemd-rtwatch make-realtime) |& grep "Too few arguments" >/dev/null
(! systemd-rtwatch make-realtime 1) |& grep "Too few arguments" >/dev/null
(! systemd-rtwatch make-realtime 1 5 7) |& grep "Too many arguments" >/dev/null
(! systemd-rtwatch make-realtime foo 5) |& grep "Failed to pin process 'foo'" >/dev/null
(! systemd-rtwatch make-realtime 1 foo) |& grep "Failed to parse priority 'foo'" >/dev/null
(! systemd-rtwatch make-high-priority 1 foo) |& grep "Failed to parse nice level 'foo'" >/dev/null
(! systemd-rtwatch make-high-priority -- 1 -21) |& grep "Failed to parse nice level '-21'" >/dev/null
(! systemd-rtwatch --thread=foo make-realtime 1 5) |& grep "Failed to parse thread ID 'foo'" >/dev/null
(! systemd-rtwatch --thread=0 make-realtime 1 5) |& grep "Failed to parse thread ID '0'" >/dev/null
(! systemd-rtwatch --json=foo status)
(! systemd-rtwatch --no-such-option)

# The service is socket activated, hence the first request starts it
systemd-rtwatch status
systemctl is-active systemd-rtwatchd.service
systemd-rtwatch --json=short status | jq -e '.schedulingPolicy == "rr" and .maxRealtimePriority == 20 and .minNiceLevel == -15 and .suspended == false'
# 'status' is the default verb, and -j is short for --json=pretty/--json=short
systemd-rtwatch | grep "Scheduling policy: rr" >/dev/null
systemd-rtwatch -j | jq -e '.schedulingPolicy == "rr"'
systemd-rtwatch --json=pretty status | jq -e '.maxRealtimePriority == 20'

# Listing works with nothing to list, too
systemd-rtwatch list |& grep "No realtime or high priority threads." >/dev/null
systemd-rtwatch --json=short list | jq -e 'length == 0'
systemd-rtwatch --json=pretty list | jq -e 'length == 0'
varlinkctl introspect /run/systemd/io.systemd.RTWatch io.systemd.RTWatch

# A process that has RLIMIT_RTTIME set (bash' ulimit -R takes µs), and one that has not
(ulimit -R 100000; exec sleep infinity) &
PID=$!
sleep infinity &
PID_NO_RTTIME=$!

# Realtime scheduling via Varlink
assert_policy "$PID" SCHED_OTHER
systemd-rtwatch --no-ask-password make-realtime "$PID" 5
assert_policy "$PID" "SCHED_RR|SCHED_RESET_ON_FORK"
assert_priority "$PID" 5
systemd-rtwatch --json=short status | jq -e '.users == 1 and .processes == 1 and .threads == 1'

# Specifying the thread explicitly works too, and so does a ThreadId object with only the process set
systemd-rtwatch make-realtime --thread="$PID" "$PID" 6
assert_priority "$PID" 6
varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.MakeThreadRealtime "{\"thread\":{\"process\":{\"pid\":$PID}},\"priority\":7}"
assert_priority "$PID" 7

# List() enumerates the threads we handed out realtime scheduling to, but only with the 'more' flag, and
# unprivileged clients only see their own threads
systemd-rtwatch list
systemd-rtwatch list | grep -E "^\s*0\s+$PID\s+$PID\s+sleep\s+7\s" >/dev/null
systemd-rtwatch list | grep "sleep infinity" >/dev/null
systemd-rtwatch --json=short list | jq -e "length == 1 and .[0].thread.process.pid == $PID and .[0].thread.tid == $PID and .[0].priority == 7 and .[0].userId == 0"
systemd-rtwatch --json=short list | jq -e '.[0].threadName == "sleep" and .[0].commandLine == ["sleep", "infinity"] and (.[0].unit | type) == "string" and (.[0] | has("niceLevel") | not)'
(! varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.List '{}')
varlinkctl call --more /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.List '{}' | jq --seq -e "select(.thread.tid == $PID) | .priority == 7"
setpriv --reuid=testuser --regid=testuser --clear-groups systemd-rtwatch --json=short list | jq -e 'length == 0'

# If thread pidfds are supported (kernel 6.9+), the ThreadId includes the inode number of the thread's pidfd,
# which may be passed back to make sure the right thread is referenced
THREAD_PIDFD_ID="$(systemd-rtwatch --json=short list | jq -r '.[0].thread.pidfdId // empty')"
if [[ -n "$THREAD_PIDFD_ID" ]]; then
    varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.MakeThreadRealtime "{\"thread\":{\"process\":{\"pid\":$PID},\"tid\":$PID,\"pidfdId\":$THREAD_PIDFD_ID},\"priority\":7}"
    (! varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.MakeThreadRealtime "{\"thread\":{\"process\":{\"pid\":$PID},\"tid\":$PID,\"pidfdId\":$((THREAD_PIDFD_ID + 1))},\"priority\":7}") |& grep NoSuchThread >/dev/null
fi

# Requests violating the policy are refused, and the client tool reports why
(! systemd-rtwatch make-realtime "$PID" 20000) |& grep "Invalid argument" >/dev/null
(! systemd-rtwatch make-realtime "$PID" 21) |& grep "Invalid argument" >/dev/null
(! systemd-rtwatch make-realtime "$PID_NO_RTTIME" 5) |& grep "io.systemd.RTWatch.RealtimeTimeLimitNotSet" >/dev/null
(! systemd-rtwatch make-realtime --thread=1 "$PID" 5) |& grep "io.systemd.RTWatch.NoSuchThread" >/dev/null
(! systemd-rtwatch make-high-priority -- "$PID" -16) |& grep "Invalid argument" >/dev/null
(! varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.MakeThreadRealtime "{\"thread\":{\"process\":{\"pid\":$PID},\"tid\":-1},\"priority\":5}") |& grep "Invalid argument" >/dev/null
(! varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.MakeThreadRealtime "{\"thread\":{\"process\":{\"pid\":$PID_NO_RTTIME}},\"priority\":5}") |& grep RealtimeTimeLimitNotSet >/dev/null
assert_policy "$PID_NO_RTTIME" SCHED_OTHER

systemd-rtwatch reset-known
assert_policy "$PID" SCHED_OTHER
assert_nice "$PID" 0

# Promotions and demotions are logged as structured messages
journalctl --sync
[[ -n "$(journalctl -b -q MESSAGE_ID=6e8429295baa4dc1a9a45464a064fa58 RTWATCH_PID="$PID" RTWATCH_TID="$PID" RTWATCH_UID=0 RTWATCH_PRIORITY=5)" ]]
[[ -n "$(journalctl -b -q MESSAGE_ID=246eb1ce01f240da846d5000898fbeb6 RTWATCH_PID="$PID" RTWATCH_TID="$PID")" ]]
journalctl -b -x -n 1 MESSAGE_ID=246eb1ce01f240da846d5000898fbeb6 | grep "has been demoted" >/dev/null

# High priority, no RLIMIT_RTTIME needed for this
systemd-rtwatch make-high-priority -- "$PID_NO_RTTIME" -5
assert_policy "$PID_NO_RTTIME" "SCHED_OTHER|SCHED_RESET_ON_FORK"
assert_nice "$PID_NO_RTTIME" -5
systemd-rtwatch --json=short list | jq -e "length == 1 and .[0].thread.process.pid == $PID_NO_RTTIME and .[0].niceLevel == -5 and (.[0] | has(\"priority\") | not)"
(! systemd-rtwatch make-high-priority -- "$PID_NO_RTTIME" -20)
assert_nice "$PID_NO_RTTIME" -5
systemd-rtwatch make-high-priority --thread="$PID_NO_RTTIME" -- "$PID_NO_RTTIME" -4
assert_nice "$PID_NO_RTTIME" -4
systemd-rtwatch list | grep -E "^\s*0\s+$PID_NO_RTTIME\s+$PID_NO_RTTIME\s+sleep\s+-\s+-4\s" >/dev/null
systemd-rtwatch reset-known
assert_nice "$PID_NO_RTTIME" 0
systemd-rtwatch --json=short list | jq -e 'length == 0'

# Suspend/resume demotes and promotes again
systemd-rtwatch make-realtime "$PID" 5
systemd-rtwatch suspend
assert_policy "$PID" SCHED_OTHER
systemd-rtwatch --json=short status | jq -e '.suspended == true'
systemd-rtwatch | grep "Suspended: yes" >/dev/null
(! systemd-rtwatch make-realtime "$PID" 5) |& grep "io.systemd.RTWatch.Suspended" >/dev/null
systemd-rtwatch resume
assert_policy "$PID" "SCHED_RR|SCHED_RESET_ON_FORK"
assert_priority "$PID" 5
systemd-rtwatch --json=short status | jq -e '.suspended == false'

# Watch() reports events, but only to privileged clients, and only with the 'more' flag
(! varlinkctl call /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.Watch '{}')
(! setpriv --reuid=testuser --regid=testuser --clear-groups varlinkctl call --more /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.Watch '{}')
systemd-rtwatch reset-known
varlinkctl call --more /run/systemd/io.systemd.RTWatch io.systemd.RTWatch.Watch '{}' >"$WATCH_LOG" &
WATCH_PID=$!
timeout 30 bash -c "until grep '\"ready\"' '$WATCH_LOG' >/dev/null; do sleep .1; done"
systemd-rtwatch make-realtime "$PID" 5
systemd-rtwatch make-high-priority -- "$PID_NO_RTTIME" -5
systemd-rtwatch suspend
systemd-rtwatch resume
systemd-rtwatch reset-known
timeout 30 bash -c "until grep '\"reset_known\"' '$WATCH_LOG' >/dev/null; do sleep .1; done"
kill "$WATCH_PID"
wait "$WATCH_PID" || :
WATCH_PID=""
cat "$WATCH_LOG"
[[ "$(jq --seq -r '.event' <"$WATCH_LOG" | tr '\n' ' ')" == "ready realtime high_priority suspended resumed reset_known " ]]
jq --seq -e "select(.event == \"realtime\") | .thread.process.pid == $PID and .thread.tid == $PID and .priority == 5 and .userId == 0" <"$WATCH_LOG"
jq --seq -e 'select(.event == "realtime") | .threadName == "sleep" and .commandLine == ["sleep", "infinity"] and (.unit | type) == "string"' <"$WATCH_LOG"
jq --seq -e "select(.event == \"high_priority\") | .thread.process.pid == $PID_NO_RTTIME and .niceLevel == -5 and .threadName == \"sleep\"" <"$WATCH_LOG"
jq --seq -e 'select(.event == "suspended") | .affectedThreads == 2' <"$WATCH_LOG"
jq --seq -e 'select(.event == "resumed") | .affectedThreads == 2' <"$WATCH_LOG"
jq --seq -e 'select(.event == "reset_known") | .affectedThreads == 2' <"$WATCH_LOG"
assert_policy "$PID" SCHED_OTHER
assert_nice "$PID_NO_RTTIME" 0

# reset-all demotes realtime threads we don't know about too, but not root's by default, hence run one as
# another user
systemd-rtwatch reset-known
setpriv --reuid=testuser --regid=testuser --clear-groups bash -c 'ulimit -R 100000; exec sleep infinity' &
PID_FOREIGN=$!
# Wait until setpriv changed UID and exec'ed sleep, before making it realtime
timeout 30 bash -c "until [[ \$(stat -c %U /proc/$PID_FOREIGN) == testuser && \$(</proc/$PID_FOREIGN/comm) == sleep ]]; do sleep .1; done"
chrt -r -p 3 "$PID_FOREIGN"
assert_policy "$PID_FOREIGN" SCHED_RR
systemd-rtwatch reset-all
assert_policy "$PID_FOREIGN" SCHED_OTHER
kill "$PID_FOREIGN"

# Unprivileged clients may not use the privileged calls
(! setpriv --reuid=testuser --regid=testuser --clear-groups systemd-rtwatch reset-known)
(! setpriv --reuid=testuser --regid=testuser --clear-groups systemd-rtwatch --no-ask-password reset-all)
(! setpriv --reuid=testuser --regid=testuser --clear-groups systemd-rtwatch suspend)
(! setpriv --reuid=testuser --regid=testuser --clear-groups systemd-rtwatch --no-ask-password resume)
setpriv --reuid=testuser --regid=testuser --clear-groups systemd-rtwatch status

# The classic RealtimeKit D-Bus API
busctl introspect org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1
busctl get-property org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 MaxRealtimePriority | grep "i 20" >/dev/null
busctl get-property org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 MinNiceLevel | grep "i -15" >/dev/null
busctl get-property org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 RTTimeUSecMax | grep "x 200000" >/dev/null
busctl call org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 MakeThreadRealtimeWithPID ttu "$PID" 0 8
assert_priority "$PID" 8
# (busctl shows all org.freedesktop.DBus.Error.AccessDenied errors as "Access denied")
(! busctl call org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 MakeThreadRealtimeWithPID ttu "$PID_NO_RTTIME" 0 8) |& grep "Access denied" >/dev/null
busctl call -- org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 MakeThreadHighPriorityWithPID tti "$PID_NO_RTTIME" 0 -3
assert_nice "$PID_NO_RTTIME" -3
busctl call org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 ResetKnown
assert_policy "$PID" SCHED_OTHER
assert_nice "$PID_NO_RTTIME" 0
# The management methods are authorized via polkit, the same way as their Varlink counterparts
for method in ResetKnown ResetAll Suspend Resume; do
    (! setpriv --reuid=testuser --regid=testuser --clear-groups \
          busctl call org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 "$method")
done
busctl call org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 Suspend
systemd-rtwatch | grep "Suspended: yes" >/dev/null
busctl call org.freedesktop.RealtimeKit1 /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 Resume
systemd-rtwatch | grep "Suspended: no" >/dev/null

# Processes and threads are pinned via pidfds, hence are forgotten as soon as they exit, without any further
# request triggering garbage collection
systemd-rtwatch --json=short status | jq -e '.processes == 0 and .threads == 0'
(ulimit -R 100000; exec sleep infinity) &
PID_EXIT=$!
systemd-rtwatch make-realtime "$PID_EXIT" 5
systemd-rtwatch --json=short status | jq -e '.processes == 1 and .threads == 1'
kill "$PID_EXIT"
wait "$PID_EXIT" || :
timeout 30 bash -c "until systemd-rtwatch --json=short status | jq -e '.processes == 0 and .threads == 0' >/dev/null; do sleep .1; done"

# On exit everything known is demoted
systemd-rtwatch make-realtime "$PID" 5
systemctl stop systemd-rtwatchd.service
assert_policy "$PID" SCHED_OTHER

# … and the service is activated again on the next request
systemd-rtwatch status

# Settings may be configured in rtwatchd.conf, but the command line takes precedence
mkdir -p /run/systemd/rtwatchd.conf.d
cat >/run/systemd/rtwatchd.conf.d/50-test.conf <<EOF
[RTWatch]
MaxRealtimePriority=15
MinNiceLevel=-10
EOF
restart_rtwatchd
systemd-rtwatch --json=short status | jq -e '.maxRealtimePriority == 15 and .minNiceLevel == -10'
(! systemd-rtwatch make-realtime "$PID" 16) |& grep "Invalid argument" >/dev/null
systemd-rtwatch make-realtime "$PID" 15
assert_priority "$PID" 15
mkdir -p /run/systemd/system/systemd-rtwatchd.service.d
cat >/run/systemd/system/systemd-rtwatchd.service.d/50-test.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-rtwatchd --min-nice-level=-12
EOF
systemctl daemon-reload
restart_rtwatchd
assert_policy "$PID" SCHED_OTHER
systemd-rtwatch --json=short status | jq -e '.maxRealtimePriority == 15 and .minNiceLevel == -12'

# Invalid settings in the configuration file are ignored
cat >/run/systemd/rtwatchd.conf.d/60-invalid.conf <<EOF
[RTWatch]
MaxRealtimePriority=foo
UsersMax=0
SchedulingPolicy=batch
EOF
restart_rtwatchd
systemd-rtwatch --json=short status | jq -e '.maxRealtimePriority == 15 and .minNiceLevel == -12'

# … but invalid combinations of settings are refused
cat >/run/systemd/rtwatchd.conf.d/60-invalid.conf <<EOF
[RTWatch]
CanaryCheepSec=20s
EOF
(! restart_rtwatchd)
rm -rf /run/systemd/rtwatchd.conf.d /run/systemd/system/systemd-rtwatchd.service.d
systemctl daemon-reload
restart_rtwatchd
systemd-rtwatch --json=short status | jq -e '.maxRealtimePriority == 20 and .minNiceLevel == -15'
