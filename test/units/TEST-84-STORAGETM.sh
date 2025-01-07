#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-analyze compare-versions "$(nvme --version | grep libnvme | awk '{print $3}')" eq 1.11; then
    if grep -q "CONFIG_NVME_TCP_TLS is not set" "/boot/config-$(uname -r)" 2>/dev/null || grep -q "CONFIG_NVME_TCP_TLS is not set" "/usr/lib/modules/$(uname -r)/config" 2>/dev/null; then
        # See: https://github.com/linux-nvme/nvme-cli/issues/2573
        echo "nvme-cli is broken and requires TLS support in the kernel" >/skipped
        exit 77
    fi
fi

/usr/lib/systemd/systemd-storagetm --list-devices

modprobe -v nvmet-tcp
modprobe -v nvme-tcp

systemctl start sys-kernel-config.mount

dd if=/dev/urandom of=/var/tmp/storagetm.test bs=1024 count=10240

NVME_UUID="$(cat /proc/sys/kernel/random/uuid)"
systemd-run -u teststoragetm.service -p Type=notify -p "Environment=SYSTEMD_NVME_UUID=${NVME_UUID:?}" /usr/lib/systemd/systemd-storagetm /var/tmp/storagetm.test --nqn=quux
NVME_DEVICE="/dev/disk/by-id/nvme-uuid.${NVME_UUID:?}"

nvme connect-all -t tcp -a 127.0.0.1 -s 16858 --hostid="$(cat /proc/sys/kernel/random/uuid)"
udevadm wait --settle "$NVME_DEVICE"

dd if="$NVME_DEVICE" bs=1024 | cmp /var/tmp/storagetm.test -

nvme disconnect-all
systemctl stop teststoragetm.service
rm /var/tmp/storagetm.test

touch /testok
