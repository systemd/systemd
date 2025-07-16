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

# The following test will return 77 if at compile time the libbpf version
# is less than 1.5.0 or libbpf support is disabled.
# It fails if fsopen()/fsconfig() bpffs is not supported.
set +e
/usr/lib/systemd/tests/unit-tests/manual/test-bpf-token
RET_TEST_BPF_TOKEN=$?
set -e

if (( RET_TEST_BPF_TOKEN != 0 && RET_TEST_BPF_TOKEN != 77 )); then
    # Check if PrivateBPF=yes is gracefully ignored.
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

# Check that with PrivateBPF=yes, a new bpffs instance is mounted
systemd-run --wait \
        -p PrivateUsers=yes \
        -p PrivateMounts=yes \
        -p DelegateNamespaces=mnt \
        -p PrivateBPF=yes \
        grep -q '^none /sys/fs/bpf bpf rw' /proc/mounts

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

if (( RET_TEST_BPF_TOKEN == 77 )); then
   echo "libbpf is not supported or older than v1.5, skipping bpf token tests."
   exit 0
fi

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
