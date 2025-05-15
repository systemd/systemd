#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p ProtectKernelTunables=yes -p PrivateBPF=no --wait true
systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p PrivateBPF=yes --wait true

# Check that the bpffs mount flags are in place
systemd-run \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        -p BPFDelegateCommands=BPFObjPin,BPFBtfLoad,BPFMapFreeze,BPFLinkDetach \
        --wait \
        grep -q obj_pin:btf_load:map_freeze:link_detach /proc/mounts

# The following test will return 77 if libbpf < 1.5.0, if it happens don't let the whole test fail
set +e

systemd-run \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        -p BPFDelegateCommands=BPFProgLoad \
        --wait \
        /usr/lib/systemd/tests/unit-tests/manual/test-bpf-token
ret=$?

if [ $ret -ne 77 ] && [ $ret -ne 0 ]; then
        exit 1
fi
