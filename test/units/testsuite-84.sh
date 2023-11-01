#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

modprobe -v nvmet-tcp
modprobe -v nvme-tcp

systemctl start sys-kernel-config.mount

dd if=/dev/urandom of=/var/tmp/storagetm.test bs=1024 count=10240

systemd-run -u teststoragetm.service -p Type=notify /usr/lib/systemd/systemd-storagetm /var/tmp/storagetm.test --nqn=quux

nvme connect-all -t tcp -a 127.0.0.1 -s 16858 --hostid="$(cat /proc/sys/kernel/random/uuid)"

dd if=/dev/nvme1n1 bs=1024 | cmp /var/tmp/storagetm.test -

nvme disconnect --device=nvme1

systemctl stop teststoragetm.service

rm /var/tmp/storagetm.test

touch /testok
