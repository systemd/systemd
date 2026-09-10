#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests that the log extra fields state file is created while the unit runs
# and removed again when it exits
unit="log-extra-fields-$RANDOM.service"
systemd-run --service-type=exec --unit="$unit" \
            -p LogExtraFields=FOO=bar \
            sleep 60
test -e "/run/systemd/units/log-extra-fields:$unit"
systemctl stop "$unit"
timeout 30 bash -c "while [ -e '/run/systemd/units/log-extra-fields:$unit' ]; do sleep .5; done"
