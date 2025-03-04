#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

SYSTEMD_IN_CHROOT=1 systemd-detect-virt --chroot
(! SYSTEMD_IN_CHROOT=0 systemd-detect-virt --chroot)
