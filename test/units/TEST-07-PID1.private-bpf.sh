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

# Building test-bpf-token requires BPF support
if systemctl --version | grep -q -- -BPF_FRAMEWORK; then
        exit 0
fi

SKIP_TOKEN_TESTS=
# The following test will always return 77 if at compile time the libbpf version
# is less than 1.5.0. If it happens don't let the whole test fail
set +e

/usr/lib/systemd/tests/unit-tests/manual/test-bpf-token
if (( $? == 77 )); then
    SKIP_TOKEN_TESTS=1
elif (( $? != 0 )); then
    # fsopen()/fsconfig() does not work, skip all remaining tests
    echo "fsopen()/fsconfig() for bpffs does not work, skipping tests for PrivateBPF=yes."
    exit 0
fi

set -e

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

if [[ -n "$SKIP_TOKEN_TESTS" ]];
   echo "libbpf is not supported or old, skipping bpt token tests."
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
