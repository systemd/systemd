#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

FSTYPE="$(stat --file-system --format "%T" /)"

if [[ "$FSTYPE" == "fuseblk" ]]; then
    echo "Root filesystem is virtiofs, skipping"
    exit 77
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

run_subtests

touch /testok
