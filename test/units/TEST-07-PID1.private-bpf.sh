#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ux
set -o pipefail

[ -d /sys/fs/bpf ] || exit 77

systemd-run -p PrivateBPF=no --wait true
if ! systemd-run -p PrivateBPF=yes --wait true; then
        journalctl --no-pager -p info |tail -40
        journalctl --no-pager -p warning |tail -10
        i=3
        while [ $i -gt 0 ]; do
                echo "ls bpf, try $i"
                ls -ld /sys /sys/fs /sys/fs/bpf && break
                i=$((i - 1))
                sleep 3
        done
        uname -a
        grep bpf /proc/filesystems
        cat /proc/cmdline
        sysctl -a |grep -i bpf
        journalctl --no-pager --dmesg --grep=bpf --case-sensitive=no
        exit 1
fi
