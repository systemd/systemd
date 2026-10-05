#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Confidential Computing test.
#
# These only run on coco hardware and if the test environment isn't already virtualized, see
# the harness --coco= flag and the documentation in test/integration-tests/README.md.
#
# Subtests are split per platform and launch path to reduce the number of required boots.
# Test code runs on both sides:
#   - host: test vmspawn by running confidential guests. TEST-94-COCO/lib.sh provides helpers.
#   - guest: test guest side component coco behavior. Assertions via TEST-94-COCO/guest-test{,-runner}.sh.

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh
# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which doesn't work under ASan, skipping" | tee --append /skipped
    exit 77
fi

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping" | tee --append /skipped
    exit 77
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping" | tee --append /skipped
    exit 77
fi

if ! vmspawn_images_dir >/dev/null; then
    echo "image artifacts not found in /work/vm-images, skipping" | tee --append /skipped
    exit 77
fi

# The integration-test-wrapper resolves the host's coco technology (where /sys/module is readable) and
# passes it via $COCO_TYPE.
if [[ -z "${COCO_TYPE:-}" ]]; then
    echo "COCO_TYPE not set (run via the integration harness with --coco), skipping" | tee --append /skipped
    exit 77
fi
echo "Host coco type: $COCO_TYPE"

run_subtests_and_exit
