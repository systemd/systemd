#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test TrustedExec= BPF enforcement.
#
# Uses a C test helper to load the BPF program with initramfs_s_dev set to the
# current rootfs s_dev, then verifies that execution from tmpfs is blocked
# while execution from the rootfs continues to work. If dm-verity signing
# support is available, also tests execution from a signed verity device.
#
# Requires the VM to be booted with dm-verity.require_signatures=1 on the
# kernel command line (set in the test's meson.build).
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Skip if prerequisites not met
if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
    echo "BPF framework not compiled in, skipping"
    exit 0
fi

if ! kernel_supports_lsm bpf; then
    echo "BPF LSM not available in kernel, skipping"
    exit 0
fi

if [[ -v ASAN_OPTIONS ]]; then
    echo "Skipping enforcement test under sanitizers"
    exit 0
fi

HELPER="/usr/lib/systemd/tests/unit-tests/manual/test-bpf-trusted-exec"
if [[ ! -x "$HELPER" ]]; then
    echo "test-bpf-trusted-exec helper not found at $HELPER, skipping"
    exit 0
fi

# require_signatures is read-only — must be set via kernel cmdline
if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    modprobe dm_verity 2>/dev/null || true
fi
if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    echo "dm_verity module not available, skipping enforcement test"
    exit 0
fi
val="$(cat /sys/module/dm_verity/parameters/require_signatures)"
if [[ "$val" != "Y" && "$val" != "1" ]]; then
    echo "require_signatures not enabled (need dm-verity.require_signatures=1 on cmdline), skipping"
    exit 0
fi

at_exit() {
    set +e
    # Always clean up BPF pins
    "$HELPER" detach 2>/dev/null || true
    # Clean up tmpfs test directory
    umount /tmp/trusted-exec-test 2>/dev/null || true
    rm -rf /tmp/trusted-exec-test
    # Clean up verity test artifacts
    if [[ -e /dev/mapper/test-trusted-exec-verity ]]; then
        umount /tmp/verity-mount 2>/dev/null || true
        veritysetup close test-trusted-exec-verity 2>/dev/null || true
    fi
    rm -rf /tmp/verity-mount /tmp/trusted-exec-workdir
}
trap at_exit EXIT

# ------ Baseline: verify tmpfs exec works WITHOUT our BPF ------

mkdir -p /tmp/trusted-exec-baseline
mount -t tmpfs tmpfs /tmp/trusted-exec-baseline
cp /usr/bin/true /tmp/trusted-exec-baseline/true-baseline
chmod +x /tmp/trusted-exec-baseline/true-baseline
if ! /tmp/trusted-exec-baseline/true-baseline 2>/dev/null; then
    echo "WARNING: tmpfs exec blocked BEFORE BPF attach (another LSM?)" >&2
    echo "Skipping enforcement test — baseline tmpfs exec fails"
    umount /tmp/trusted-exec-baseline; rm -rf /tmp/trusted-exec-baseline
    exit 0
fi
echo "Baseline: tmpfs exec works without BPF"
umount /tmp/trusted-exec-baseline; rm -rf /tmp/trusted-exec-baseline

# ------ Attach BPF with rootfs trusted ------

"$HELPER" attach

# ------ Test: Rootfs execution still works ------

/usr/bin/true
echo "Rootfs execution: OK"

# ------ Test: Execution from tmpfs is blocked ------

mkdir -p /tmp/trusted-exec-test
mount -t tmpfs tmpfs /tmp/trusted-exec-test

# Copy a binary to tmpfs
cp /usr/bin/true /tmp/trusted-exec-test/true-on-tmpfs
chmod +x /tmp/trusted-exec-test/true-on-tmpfs

# This should fail with EPERM
if /tmp/trusted-exec-test/true-on-tmpfs 2>/dev/null; then
    echo "ERROR: Execution from tmpfs should have been blocked!" >&2
    exit 1
fi
echo "Execution from tmpfs blocked: OK"

# ------ Test: PROT_EXEC mmap from tmpfs is blocked (mmap_file hook) ------

if command -v python3 >/dev/null 2>&1; then
    # Write a test file on the tmpfs mount
    dd if=/dev/zero of=/tmp/trusted-exec-test/testfile bs=4096 count=1 2>/dev/null

    # File-backed PROT_EXEC mmap should be denied.
    # The python script exits 0 if mmap succeeds (bad), 1 if denied (good).
    if python3 -c "
import mmap, os, sys
fd = os.open('/tmp/trusted-exec-test/testfile', os.O_RDONLY)
try:
    m = mmap.mmap(fd, 4096, mmap.MAP_PRIVATE, mmap.PROT_READ | mmap.PROT_EXEC)
    m.close()
    sys.exit(0)  # mmap succeeded — enforcement failed
except OSError:
    sys.exit(1)  # mmap denied — enforcement works
finally:
    os.close(fd)
" 2>/dev/null; then
        echo "ERROR: PROT_EXEC mmap of tmpfs file should have been blocked!" >&2
        exit 1
    fi
    echo "PROT_EXEC mmap from tmpfs blocked: OK"

    # Anonymous PROT_EXEC mmap should be denied (NULL file — mmap_file hook)
    if python3 -c "
import mmap, sys
try:
    m = mmap.mmap(-1, 4096, mmap.MAP_PRIVATE, mmap.PROT_READ | mmap.PROT_EXEC)
    m.close()
    sys.exit(0)  # mmap succeeded — enforcement failed
except OSError:
    sys.exit(1)  # mmap denied — enforcement works
" 2>/dev/null; then
        echo "ERROR: Anonymous PROT_EXEC mmap should have been blocked!" >&2
        exit 1
    fi
    echo "Anonymous PROT_EXEC mmap blocked: OK"
else
    echo "python3 not available, skipping mmap enforcement tests"
fi

# ------ Test: Execution from signed dm-verity device ------

if command -v veritysetup >/dev/null 2>&1 &&
   command -v mksquashfs >/dev/null 2>&1 &&
   [[ -e /usr/share/mkosi.key ]] &&
   [[ -e /usr/share/mkosi.crt ]] &&
   machine_supports_verity_keyring; then

    WORKDIR=/tmp/trusted-exec-workdir
    mkdir -p "$WORKDIR/img"

    # Create a minimal squashfs with a test binary
    cp /usr/bin/true "$WORKDIR/img/true-on-verity"
    chmod +x "$WORKDIR/img/true-on-verity"
    mksquashfs "$WORKDIR/img" "$WORKDIR/test.raw" -noappend -quiet

    # Create verity hash tree
    veritysetup format "$WORKDIR/test.raw" "$WORKDIR/test.verity" \
        --root-hash-file "$WORKDIR/test.roothash" >/dev/null

    # Sign the root hash
    openssl smime -sign -nocerts -noattr -binary \
        -in "$WORKDIR/test.roothash" \
        -inkey /usr/share/mkosi.key \
        -signer /usr/share/mkosi.crt \
        -outform der \
        -out "$WORKDIR/test.roothash.p7s"

    # Open the verity device — triggers security_bdev_setintegrity() which
    # the BPF bdev_setintegrity hook uses to populate the trusted devices map
    veritysetup open \
        "$WORKDIR/test.raw" test-trusted-exec-verity \
        "$WORKDIR/test.verity" \
        --root-hash-file "$WORKDIR/test.roothash" \
        --root-hash-signature "$WORKDIR/test.roothash.p7s"

    # Mount and try to execute
    mkdir -p /tmp/verity-mount
    mount -o ro /dev/mapper/test-trusted-exec-verity /tmp/verity-mount

    /tmp/verity-mount/true-on-verity
    echo "Execution from signed dm-verity device: OK"

    umount /tmp/verity-mount
    veritysetup close test-trusted-exec-verity
    rm -rf "$WORKDIR" /tmp/verity-mount
else
    echo "dm-verity signing not available, skipping positive verity test"
fi

# ------ Detach and verify enforcement is lifted ------

echo "Pins before detach:"
ls -la /sys/fs/bpf/test_trusted_exec_* 2>&1 || echo "(no pins found)"

"$HELPER" detach
DETACH_RC=$?
echo "Detach exit code: $DETACH_RC"

echo "Pins after detach:"
ls -la /sys/fs/bpf/test_trusted_exec_* 2>&1 || echo "(no pins found)"

# Check if BPF links/progs still exist in kernel
echo "BPF links after detach:"
bpftool link list 2>&1 | grep -i 'tracing\|lsm\|trusted' || echo "(none)"
echo "BPF progs after detach:"
bpftool prog list 2>&1 | grep -i 'lsm\|trusted' || echo "(none)"

# The detach helper uses BPF_OBJ_GET + close() to go through the synchronous
# bpf_link_put_direct() path rather than bpffs inode eviction which defers via
# schedule_work(). After detach returns, all trampolines are patched.
if [[ -x /tmp/trusted-exec-test/true-on-tmpfs ]]; then
    /tmp/trusted-exec-test/true-on-tmpfs
    echo "Execution from tmpfs after detach: OK"
fi

umount /tmp/trusted-exec-test 2>/dev/null || true
rm -rf /tmp/trusted-exec-test

echo "All enforcement tests passed"
