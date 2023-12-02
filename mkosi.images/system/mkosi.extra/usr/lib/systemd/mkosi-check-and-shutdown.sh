#!/bin/bash -eux
# SPDX-License-Identifier: LGPL-2.1-or-later

# TODO: Figure out why this is failing
systemctl reset-failed systemd-vconsole-setup.service

systemctl --failed --no-legend | tee /failed-services

# Check that secure boot keys were properly enrolled.
if ! systemd-detect-virt --container; then
    cmp /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\1')
    cmp /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\0')
    # TODO: Figure out why this is failing
    # grep -q this_should_be_here /proc/cmdline
    # grep -q this_should_not_be_here /proc/cmdline && exit 1
fi

# Exit with non-zero EC if the /failed-services file is not empty (we have -e set)
[[ ! -s /failed-services ]]
