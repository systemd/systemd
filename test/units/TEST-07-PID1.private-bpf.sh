#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p ProtectKernelTunables=yes -p PrivateBPF=no --wait true
systemd-run -p PrivateUsers=yes -p PrivateMounts=yes -p DelegateNamespaces=mnt -p PrivateBPF=yes --wait true

# Check that the bpffs mount flags are in place

check_mount_opts() {
        local delegate=$1 mnt_opts=$2
        systemd-run \
                -p PrivateUsers=yes \
                -p PrivateMounts=yes \
                -p DelegateNamespaces=mnt \
                -p PrivateBPF=yes \
                -p "$delegate" \
                --wait \
                grep -q "$mnt_opts" /proc/mounts
}

check_mount_opts BPFDelegateCommands=BPFObjPin,BPFBtfLoad,BPFMapFreeze,BPFLinkDetach delegate_cmds=obj_pin:btf_load:map_freeze:link_detach,
check_mount_opts BPFDelegateMaps=BPFMapTypeArray,BPFMapTypeCpumap,BPFMapTypeRingbuf delegate_maps=array:cpumap:ringbuf,
check_mount_opts BPFDelegatePrograms=BPFProgTypeTracepoint,BPFProgTypeXdp,BPFProgTypeTracing delegate_progs=tracepoint:xdp:tracing,
check_mount_opts BPFDelegateAttachments=BPFFlowDissector,BPFCgroupSysctl,BPFNetfilter delegate_attachs=flow_dissector:cgroup_sysctl:netfilter

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
