#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Guest memory resizing with systemd-vmspawn.
# Boots full guests from the built image.

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

if ! reason="$(can_run_vmspawn)"; then
    echo "$reason, skipping" | tee --append /skipped
    exit 77
fi

if ! vmspawn_images_dir >/dev/null; then
    echo "image artifacts not found in /work/vm-images, skipping" | tee --append /skipped
    exit 77
fi

run_subtests_and_exit
