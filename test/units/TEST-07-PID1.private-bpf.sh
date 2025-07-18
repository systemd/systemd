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
if ! systemd-run --wait \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        grep -q '^none /sys/fs/bpf bpf rw' /proc/mounts; then

    # If it does not work, maybe the kernel is old or the system has buggy ubuntu kernel.
    # Let's check if PrivateBPF=yes is ignored gracefully in that case.
    systemd-run --wait \
                -p PrivateUsers=yes \
                -p PrivateMounts=yes \
                -p DelegateNamespaces=mnt \
                -p ProtectKernelTunables=yes \
                -p PrivateBPF=yes \
                grep -q '/sys/fs/bpf .* ro,' /proc/mounts

    # Skip all remaining tests.
    exit 0
fi

# Check that when specifying the delegate arguments, the mount options are set properly
check_mount_opts() {
        local delegate=$1 mnt_opts=$2
        systemd-run --wait \
                -p PrivateUsers=yes \
                -p PrivateMounts=yes \
                -p DelegateNamespaces=mnt \
                -p PrivateBPF=yes \
                -p "$delegate" \
                grep -q "$mnt_opts" /proc/mounts
}

check_mount_opts 'BPFDelegateCommands=BPFObjPin,BPFBtfLoad,BPFMapFreeze,BPFLinkDetach' 'delegate_cmds=obj_pin:btf_load:map_freeze:link_detach'
check_mount_opts 'BPFDelegateMaps=BPFMapTypeArray,BPFMapTypeCpumap,BPFMapTypeRingbuf' 'delegate_maps=array:cpumap:ringbuf'
check_mount_opts 'BPFDelegatePrograms=BPFProgTypeTracepoint,BPFProgTypeXdp,BPFProgTypeTracing' 'delegate_progs=tracepoint:xdp:tracing'
check_mount_opts 'BPFDelegateAttachments=BPFFlowDissector,BPFCgroupSysctl,BPFNetfilter' 'delegate_attachs=flow_dissector:cgroup_sysctl:netfilter'

# Building test-bpf-token requires BPF support
if systemctl --version | grep -q -- -BPF_FRAMEWORK; then
        exit 0
fi

# The following test will always return 77 if at compile time the libbpf version
# is less than 1.5.0. If it happens don't let the whole test fail
set +e

/usr/lib/systemd/tests/unit-tests/manual/test-bpf-token
if [ $? -eq 77 ]; then
        exit 0
fi

set -e

# Check that our helper is able to get a BPF token
systemd-run --wait \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        -p BPFDelegateCommands=BPFProgLoad \
        /usr/lib/systemd/tests/unit-tests/manual/test-bpf-token

# Check that without the delegates, the helper aborts trying to get a token
(! systemd-run --wait \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        /usr/lib/systemd/tests/unit-tests/manual/test-bpf-token)
