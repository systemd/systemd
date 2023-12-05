#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-detect-virt --quiet --container; then
    exit 0
fi

if [[ ! -x /usr/bin/bootctl ]]; then
    exit 0
fi

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

bootctl install
(! bootctl update)
bootctl is-installed
bootctl random-seed

bootctl status
bootctl list

assert_eq "$(bootctl --print-esp-path)" "/efi"
assert_eq "$(bootctl --print-boot-path)" "/boot"
bootctl --print-root-device

bootctl remove
(! bootctl is-installed)
