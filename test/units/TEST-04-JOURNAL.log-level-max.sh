#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests that LogLevelMax= applies to the unit's messages, for system and user units alike
# https://github.com/systemd/systemd/issues/43446

if ! cgroupfs_supports_user_xattrs; then
    echo "CGroup does not support user xattrs, skipping LogLevelMax= tests."
    exit 0
fi

unit=""
uid="$(id -u testuser)"

cleanup() {
    systemctl --user -M testuser@ stop "$unit" 2>/dev/null || :
    systemctl stop "$unit" 2>/dev/null || :
    rm -rf "/run/systemd/system/user@$uid.service.d"
    systemctl daemon-reload || :
    systemctl stop "user@$uid.service" 2>/dev/null || :
    loginctl disable-linger testuser || :
}
trap cleanup EXIT

# Keep the user manager of testuser around while the subtests below hand control
# back and forth between the host and the user manager, so that it cannot be
# garbage-collected in between
loginctl enable-linger testuser

# Each message sender is kept alive for a moment after logging, as journald
# cannot attribute messages to the unit anymore if the sender already exited
# again when the message is processed.
# The dropped and the kept message are sent over a single stream, tagged with
# syslog level prefixes: the kept message then also proves that the dropped one
# was attributed to the unit, and hence filtered rather than lost.
# A message logged with a priority above LogLevelMax=info must be dropped by
# journald, one below must be kept

# The LogLevelMax= of a system unit must apply
unit="log-level-max-system-$RANDOM.service"
systemd-run --wait --service-type=exec --unit="$unit" \
            -p LogLevelMax=info \
            bash -ec "{ printf '<7>suppressed-debug-message\n<6>kept-info-message\n'; sleep 1; } | systemd-cat"
journalctl --sync
run_and_grep "^kept-info-message$" journalctl -q -b "_SYSTEMD_UNIT=$unit" -o cat
run_and_grep -n "^suppressed-debug-message$" journalctl -q -b "_SYSTEMD_UNIT=$unit" -o cat

# The LogLevelMax= of a user unit must apply too
# Match by _SYSTEMD_USER_UNIT instead of --user-unit=, as the latter also
# requires _UID= to match the uid of the calling journalctl, which is root
# here, but testuser for the messages below
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            -p LogLevelMax=info \
            bash -ec "{ printf '<7>suppressed-debug-message\n<6>kept-info-message\n'; sleep 1; } | systemd-cat"
journalctl --sync
run_and_grep "^kept-info-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
run_and_grep -n "^suppressed-debug-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat

# Without LogLevelMax= both messages must be kept
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            bash -ec '{ echo kept-debug-message; sleep 1; } | systemd-cat -p debug;
                       { echo kept-info-message; sleep 1; } | systemd-cat -p info'
journalctl --sync
run_and_grep "^kept-debug-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
run_and_grep "^kept-info-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat

# A LogLevelMax= set on user@<UID>.service applies to the user manager and to the
# user units of that user; a per-unit LogLevelMax= can only tighten that cap,
# not loosen it
mkdir -p "/run/systemd/system/user@$uid.service.d"
printf '[Service]\nLogLevelMax=info\n' >"/run/systemd/system/user@$uid.service.d/10-log-level-max.conf"
systemctl daemon-reload
systemctl stop "user@$uid.service"

# Without a per-unit LogLevelMax= the session-wide one applies
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            bash -ec "{ printf '<7>session-suppressed-debug-message\n<6>session-kept-info-message\n'; sleep 1; } | systemd-cat"
journalctl --sync
run_and_grep "^session-kept-info-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
run_and_grep -n "^session-suppressed-debug-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat

# A per-unit LogLevelMax= cannot loosen the session-wide cap: with
# LogLevelMax=info on user@<UID>.service and LogLevelMax=debug on the unit,
# the effective cap is the lower of the two, i.e. info
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            -p LogLevelMax=debug \
            bash -ec "{ printf '<7>unit-suppressed-debug-message\n<6>unit-kept-info-message\n'; sleep 1; } | systemd-cat"
journalctl --sync
run_and_grep "^unit-kept-info-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
run_and_grep -n "^unit-suppressed-debug-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat

# While the session-wide cap is in place, it is exported as an xattr on the
# cgroup of the user manager service itself. It is removed again once the cap
# is dropped, even though the cgroup of the still-running user manager persists
user_manager_cgroup="/sys/fs/cgroup$(systemctl show "user@$uid.service" -p ControlGroup --value)"
test "$(getfattr --absolute-names --only-values -n user.journald_log_level_max "$user_manager_cgroup")" = 6

rm -rf "/run/systemd/system/user@$uid.service.d"
systemctl daemon-reload
# The re-realization that applies the xattrs again is asynchronous, hence poll
timeout 30 bash -c "while getfattr --absolute-names --only-values -n user.journald_log_level_max '$user_manager_cgroup' >/dev/null 2>&1; do sleep .5; done"
test -d "$user_manager_cgroup"

# With the session-wide cap gone, messages of the user units pass through the
# journal unfiltered again
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
    bash -ec '{ echo recovered-debug-message; sleep 1; } | systemd-cat -p debug;
               { echo recovered-info-message; sleep 1; } | systemd-cat -p info'
journalctl --sync
run_and_grep "^recovered-debug-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
run_and_grep "^recovered-info-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat

systemctl stop "user@$uid.service"

# The log level is exported as an xattr on the unit's own cgroup, so that it is
# removed together with the cgroup again when the unit stops
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --service-type=exec --unit="$unit" \
            -p LogLevelMax=info \
            sleep 60
cgroup="/sys/fs/cgroup$(systemctl --user -M testuser@ show "$unit" -p ControlGroup --value)"
# LogLevelMax=info is exported as its numeric log level
test "$(getfattr --absolute-names --only-values -n user.journald_log_level_max "$cgroup")" = 6
systemctl --user -M testuser@ stop "$unit"
timeout 30 bash -c "while [ -e '$cgroup' ]; do sleep .5; done"

# A unit that configures no LogLevelMax= of its own gets no xattr
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --service-type=exec --unit="$unit" \
            sleep 60
cgroup="/sys/fs/cgroup$(systemctl --user -M testuser@ show "$unit" -p ControlGroup --value)"
(! getfattr --absolute-names --only-values -n user.journald_log_level_max "$cgroup" 2>/dev/null)
systemctl --user -M testuser@ stop "$unit"

# The min of the levels is also applied when the leaf is the stricter one:
# with LogLevelMax=debug on user@<UID>.service and LogLevelMax=info on the
# unit, the effective cap is the lower of the two, i.e. info
mkdir -p "/run/systemd/system/user@$uid.service.d"
printf '[Service]\nLogLevelMax=debug\n' >"/run/systemd/system/user@$uid.service.d/10-log-level-max.conf"
systemctl daemon-reload
systemctl start "user@$uid.service"
timeout 30 bash -c "while [ \"\$(getfattr --absolute-names --only-values -n user.journald_log_level_max '$user_manager_cgroup')\" != 7 ]; do sleep .5; done"

unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
    -p LogLevelMax=info \
    bash -ec "{ printf '<7>leaf-suppressed-debug-message\n<6>leaf-kept-info-message\n'; sleep 1; } | systemd-cat"
journalctl --sync
run_and_grep "^leaf-kept-info-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
run_and_grep -n "^leaf-suppressed-debug-message$" journalctl -q -b "_SYSTEMD_USER_UNIT=$unit" -o cat
