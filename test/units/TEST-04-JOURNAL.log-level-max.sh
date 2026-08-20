#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests that LogLevelMax= also applies to units of the user service manager
# https://github.com/systemd/systemd/issues/43446

unit=""
uid="$(id -u testuser)"

cleanup() {
    systemctl --user -M testuser@ stop "$unit" 2>/dev/null || :
    rm -rf "/run/systemd/system/user@$uid.service.d"
    systemctl daemon-reload || :
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
# Match by _SYSTEMD_USER_UNIT instead of --user-unit=, as the latter also
# requires _UID= to match the uid of the calling journalctl, which is root
# here, but testuser for the messages below.
# A message logged with a priority above LogLevelMax=info must be dropped by
# journald, one below must be kept
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            -p LogLevelMax=info \
            bash -ec '{ echo suppressed-debug-message; sleep 1; } | systemd-cat -p debug;
                       { echo kept-info-message; sleep 1; } | systemd-cat -p info'
journalctl --sync
journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx kept-info-message >/dev/null
(! journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx suppressed-debug-message)

# Without LogLevelMax= both messages must be kept
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            bash -ec '{ echo kept-debug-message; sleep 1; } | systemd-cat -p debug;
                       { echo kept-info-message; sleep 1; } | systemd-cat -p info'
journalctl --sync
journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx kept-debug-message >/dev/null
journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx kept-info-message >/dev/null

# A LogLevelMax= set on user@<UID>.service applies to the user units of that user
# unless the user unit configures one of its own
mkdir -p "/run/systemd/system/user@$uid.service.d"
printf '[Service]\nLogLevelMax=info\n' >"/run/systemd/system/user@$uid.service.d/10-log-level-max.conf"
systemctl daemon-reload
systemctl stop "user@$uid.service"

# Without a per-unit LogLevelMax= the session-wide one applies
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            bash -ec '{ echo session-suppressed-debug-message; sleep 1; } | systemd-cat -p debug;
                       { echo session-kept-info-message; sleep 1; } | systemd-cat -p info'
journalctl --sync
journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx session-kept-info-message >/dev/null
(! journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx session-suppressed-debug-message)

# A per-unit LogLevelMax= takes precedence over the session-wide one, even if it is looser
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            -p LogLevelMax=debug \
            bash -ec '{ echo unit-kept-debug-message; sleep 1; } | systemd-cat -p debug;
                       { echo unit-kept-info-message; sleep 1; } | systemd-cat -p info'
journalctl --sync
journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx unit-kept-debug-message >/dev/null
journalctl -q -b _SYSTEMD_USER_UNIT="$unit" -o cat | grep -Fx unit-kept-info-message >/dev/null

rm -rf "/run/systemd/system/user@$uid.service.d"
systemctl daemon-reload
systemctl stop "user@$uid.service"

# The log-level-max symlink of a user unit must exist while the unit runs and be
# removed again when it stops
unit="log-level-max-user-$RANDOM.service"
state_file="/run/user/$uid/systemd/units/log-level-max:$unit"
systemd-run --user -M testuser@ --service-type=exec --unit="$unit" \
            -p LogLevelMax=info \
            sleep 60
# The state file is a symlink to a relative and thus dangling target, so -e alone never matches
timeout 30 bash -c "while ! [ -L '$state_file' ]; do sleep .5; done"
systemctl --user -M testuser@ stop "$unit"
timeout 30 bash -c "while [ -e '$state_file' ] || [ -L '$state_file' ]; do sleep .5; done"

# A stale log-level-max symlink must be removed when the unit is started again
# without LogLevelMax=, e.g. one left behind by a previous user manager instance
unit="log-level-max-user-$RANDOM.service"
state_file="/run/user/$uid/systemd/units/log-level-max:$unit"
# The runtime directory may have been torn down together with the user manager of
# the previous subtest, so it has to be created again here
mkdir -p "$(dirname "$state_file")"
ln -s 4 "$state_file"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            /bin/true
timeout 30 bash -c "while [ -e '$state_file' ] || [ -L '$state_file' ]; do sleep .5; done"
# Distinguish the removal of the symlink from the whole runtime directory going away
test -d "/run/user/$uid"

# The log extra fields state file must be removed when the unit exits again
unit="log-extra-fields-$RANDOM.service"
systemd-run --wait --service-type=exec --unit="$unit" \
            -p LogExtraFields=FOO=bar \
            /bin/true
timeout 30 bash -c "while [ -e '/run/systemd/units/log-extra-fields:$unit' ]; do sleep .5; done"
