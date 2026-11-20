#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [[ ! -x /usr/lib/systemd/systemd-ptybrokerd ]]; then
    echo "systemd-ptybrokerd is not installed, skipping test." >/skipped
    exit 77
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

run_subtests_and_exit
