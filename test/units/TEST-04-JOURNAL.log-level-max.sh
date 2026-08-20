#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests that LogLevelMax= also applies to units of the user service manager
# https://github.com/systemd/systemd/issues/43446

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

# The log-level-max symlink of a user unit must be removed when the unit exits again
unit="log-level-max-user-$RANDOM.service"
systemd-run --user -M testuser@ --wait --service-type=exec --unit="$unit" \
            -p LogLevelMax=info \
            /bin/true
uid="$(id -u testuser)"
state_file="/run/user/$uid/systemd/units/log-level-max:$unit"
# The state file is a symlink to a relative and thus dangling target, so -e alone never matches
timeout 30 bash -c "while [ -e '$state_file' ] || [ -L '$state_file' ]; do sleep .5; done"

# The log extra fields state file must be removed when the unit exits again
unit="log-extra-fields-$RANDOM.service"
systemd-run --wait --service-type=exec --unit="$unit" \
            -p LogExtraFields=FOO=bar \
            /bin/true
timeout 30 bash -c "while [ -e '/run/systemd/units/log-extra-fields:$unit' ]; do sleep .5; done"
