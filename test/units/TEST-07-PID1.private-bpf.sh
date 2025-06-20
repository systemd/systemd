#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p ProtectKernelTunables=yes -p PrivateBPF=no --wait true
systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p PrivateBPF=yes --wait true
systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p PrivateBPF=yes -p BPFDelegateCommands=BPFProgLoad,BPFProgTestRun --wait true
