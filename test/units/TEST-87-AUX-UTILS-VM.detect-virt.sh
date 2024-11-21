#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

(! systemd-detect-virt -cq)

SYSTEMD_IN_CHROOT=1 systemd-detect-virt --chroot
(! SYSTEMD_IN_CHROOT=0 systemd-detect-virt --chroot)

unshare --mount-proc --fork --user --pid systemd-detect-virt --container
