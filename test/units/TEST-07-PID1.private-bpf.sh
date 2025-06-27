#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that with ProtectKernelTunables=yes and PrivateBPF=no, the host bpffs is remounted ro
systemd-run --wait \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p ProtectKernelTunables=yes \
        -p PrivateBPF=no \
        grep -q '/sys/fs/bpf .* ro,' /proc/mounts

# Check that with PrivateBPF=yes, a new bpffs instance is mounted
systemd-run --wait \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        grep -q '^none /sys/fs/bpf bpf rw' /proc/mounts
