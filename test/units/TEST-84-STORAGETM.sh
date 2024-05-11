#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

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
