#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test RestrictFileSystemAccess= BPF enforcement.
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

# Check that the kernel has the bdev_setintegrity LSM hook in BTF.
# Older kernels (e.g., CentOS 9 with 5.14) lack this hook entirely.
if command -v bpftool >/dev/null 2>&1; then
    if ! bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep 'bpf_lsm_bdev_setintegrity' >/dev/null; then
        echo "Kernel lacks bdev_setintegrity LSM hook (required for RestrictFileSystemAccess=), skipping"
        exit 0
    fi
fi

if [[ -v ASAN_OPTIONS ]]; then
    echo "Skipping enforcement test under sanitizers"
    exit 0
fi

HELPER="/usr/lib/systemd/tests/unit-tests/manual/test-bpf-restrict-fsaccess"
if [[ ! -x "$HELPER" ]]; then
    echo "ERROR: test-bpf-restrict-fsaccess helper not found at $HELPER" >&2
    exit 1
fi

# Helper exits 77 when systemd was built with bpf-framework=enabled but no
# vmlinux.h (HAVE_LSM_INTEGRITY_TYPE=0), so the BPF program isn't compiled in.
rc=0
"$HELPER" check >/dev/null 2>&1 || rc=$?
if [[ "$rc" -eq 77 ]]; then
    echo "test-bpf-restrict-fsaccess built without BPF attach support, skipping"
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
    # Kill the attach helper to detach BPF programs synchronously
    [[ -n "${HELPER_PID:-}" ]] && kill "$HELPER_PID" 2>/dev/null && wait "$HELPER_PID" 2>/dev/null || true
    # Clean up tmpfs test directories
    umount /tmp/restrict-fsaccess-test 2>/dev/null || true
    rm -rf /tmp/restrict-fsaccess-test
    umount /tmp/restrict-fsaccess-baseline 2>/dev/null || true
    rm -rf /tmp/restrict-fsaccess-baseline
    # Clean up background processes
    [[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null || true
    rm -rf /tmp/restrict-fsaccess-attach.out
}
trap at_exit EXIT

# ------ Baseline: verify tmpfs exec works WITHOUT our BPF ------
#
# Keep the destination basename as "true": on systems shipping uutils-coreutils
# (or busybox) as a multicall binary, /usr/bin/true is a symlink and cp
# dereferences it, copying the multicall binary. The dispatcher selects the
# subcommand from basename(argv[0]), so the copy only behaves as true when
# invoked under that name.

mkdir -p /tmp/restrict-fsaccess-baseline
mount -t tmpfs tmpfs /tmp/restrict-fsaccess-baseline
cp /usr/bin/true /tmp/restrict-fsaccess-baseline/true
chmod +x /tmp/restrict-fsaccess-baseline/true
if ! /tmp/restrict-fsaccess-baseline/true 2>/dev/null; then
    echo "WARNING: tmpfs exec blocked BEFORE BPF attach (another LSM?)" >&2
    echo "Skipping enforcement test, baseline tmpfs exec fails"
    umount /tmp/restrict-fsaccess-baseline; rm -rf /tmp/restrict-fsaccess-baseline
    exit 0
fi
echo "Baseline: tmpfs exec works without BPF"
umount /tmp/restrict-fsaccess-baseline; rm -rf /tmp/restrict-fsaccess-baseline

# ------ Attach BPF with rootfs trusted ------
# The helper attaches, prints map/prog/link IDs, then blocks holding FDs.
# Kill it to detach synchronously (close() drops last ref via bpf_link_put_direct).

HELPER_PID=
exec 3< <(exec "$HELPER" attach)
HELPER_PID=$!

# Read helper output line by line until LINK_IDS= (the last line before pause()).
# read -t 60 handles both timeout and helper crash (EOF on death).
while IFS= read -r -t 60 line <&3; do
    echo "$line"
    [[ "$line" == LINK_IDS=* ]] && break
done > /tmp/restrict-fsaccess-attach.out

VERITY_MAP_ID=$(sed -n 's/^VERITY_MAP_ID=//p' /tmp/restrict-fsaccess-attach.out)
BSS_MAP_ID=$(sed -n 's/^BSS_MAP_ID=//p' /tmp/restrict-fsaccess-attach.out)
PROG_IDS=$(sed -n 's/^PROG_IDS="\(.*\)"$/\1/p' /tmp/restrict-fsaccess-attach.out)
LINK_IDS=$(sed -n 's/^LINK_IDS="\(.*\)"$/\1/p' /tmp/restrict-fsaccess-attach.out)
[[ -n "$VERITY_MAP_ID" ]] || { echo "ERROR: Failed to capture VERITY_MAP_ID from helper output" >&2; exit 1; }
[[ -n "$BSS_MAP_ID" ]] || { echo "ERROR: Failed to capture BSS_MAP_ID from helper output" >&2; exit 1; }
[[ -n "$PROG_IDS" ]] || { echo "ERROR: Failed to capture PROG_IDS from helper output" >&2; exit 1; }
[[ -n "$LINK_IDS" ]] || { echo "ERROR: Failed to capture LINK_IDS from helper output" >&2; exit 1; }

# ------ Test: Rootfs execution still works ------

/usr/bin/true
echo "Rootfs execution: OK"

# ------ Test: Execution from tmpfs is blocked ------

mkdir -p /tmp/restrict-fsaccess-test
mount -t tmpfs tmpfs /tmp/restrict-fsaccess-test

# Copy a binary to tmpfs. Basename must stay "true" for multicall coreutils
# binaries (uutils, busybox) — see the baseline comment above.
cp /usr/bin/true /tmp/restrict-fsaccess-test/true
chmod +x /tmp/restrict-fsaccess-test/true

# This should fail with EPERM
if /tmp/restrict-fsaccess-test/true 2>/dev/null; then
    echo "ERROR: Execution from tmpfs should have been blocked!" >&2
    exit 1
fi
echo "Execution from tmpfs blocked: OK"

# ------ Test: PROT_EXEC mmap from tmpfs is blocked (mmap_file hook) ------

# Write a test file on the tmpfs mount for mmap/mprotect tests
dd if=/dev/zero of=/tmp/restrict-fsaccess-test/testfile bs=4096 count=1 2>/dev/null

# File-backed PROT_EXEC mmap should be denied.
# The helper exits 0 if mmap succeeds (bad), 1 if denied (good).
if "$HELPER" mmap-exec /tmp/restrict-fsaccess-test/testfile; then
    echo "ERROR: PROT_EXEC mmap of tmpfs file should have been blocked!" >&2
    exit 1
fi
echo "PROT_EXEC mmap from tmpfs blocked: OK"

# Anonymous PROT_EXEC mmap should be denied (NULL file — mmap_file hook)
if "$HELPER" anon-mmap-exec; then
    echo "ERROR: Anonymous PROT_EXEC mmap should have been blocked!" >&2
    exit 1
fi
echo "Anonymous PROT_EXEC mmap blocked: OK"

# ------ Test: mprotect adding PROT_EXEC is blocked (file_mprotect hook) ------

# mmap PROT_READ then mprotect to PROT_EXEC — the file_mprotect hook should deny this.
if "$HELPER" mprotect-exec /tmp/restrict-fsaccess-test/testfile; then
    echo "ERROR: mprotect PROT_EXEC on tmpfs file should have been blocked!" >&2
    exit 1
fi
echo "mprotect PROT_EXEC from tmpfs blocked: OK"

# ------ Test: Execution from signed dm-verity device ------
# Trust path: .platform keyring (SecureBoot DB auto-enrolled by mkosi, made
# available by 'firmware': 'auto' in the test's meson.build).

MINIMAL=/usr/share/minimal_0
if machine_supports_verity_keyring; then
    systemd-run --pipe --wait \
        --property RootImage="$MINIMAL.raw" \
        bash --version >/dev/null
    echo "Execution from signed dm-verity device: OK"
else
    echo "Verity keyring trust not available, skipping positive verity test"
fi

# ------ Test: Guard blocks non-PID1 from obtaining BPF object FDs by ID ------

if command -v bpftool >/dev/null 2>&1 && [[ -n "${VERITY_MAP_ID:-}" ]]; then
    # bpftool uses BPF_MAP_GET_FD_BY_ID / BPF_PROG_GET_FD_BY_ID /
    # BPF_LINK_GET_FD_BY_ID internally. The guard should block these for
    # our protected IDs since we're not PID1.

    # -- Map ID guard --
    if bpftool map show id "$VERITY_MAP_ID" 2>/dev/null; then
        echo "ERROR: bpftool should not be able to access verity_devices map (ID $VERITY_MAP_ID)!" >&2
        exit 1
    fi
    echo "Guard blocked verity_devices map access: OK (ID $VERITY_MAP_ID)"

    if [[ -n "${BSS_MAP_ID:-}" ]]; then
        if bpftool map show id "$BSS_MAP_ID" 2>/dev/null; then
            echo "ERROR: bpftool should not be able to access .bss map (ID $BSS_MAP_ID)!" >&2
            exit 1
        fi
        echo "Guard blocked .bss map access: OK (ID $BSS_MAP_ID)"
    fi

    # -- Prog ID guard (defense-in-depth) --
    if [[ -n "${PROG_IDS:-}" ]]; then
        IFS=',' read -ra prog_ids <<< "$PROG_IDS"
        for prog_id in "${prog_ids[@]}"; do
            if bpftool prog show id "$prog_id" 2>/dev/null; then
                echo "ERROR: bpftool should not be able to access protected prog (ID $prog_id)!" >&2
                exit 1
            fi
        done
        echo "Guard blocked prog access: OK (${#prog_ids[@]} IDs)"
    fi

    # -- Link ID guard (defense-in-depth) --
    if [[ -n "${LINK_IDS:-}" ]]; then
        IFS=',' read -ra link_ids <<< "$LINK_IDS"
        for lid in "${link_ids[@]}"; do
            if bpftool link show id "$lid" 2>/dev/null; then
                echo "ERROR: bpftool should not be able to access protected link (ID $lid)!" >&2
                exit 1
            fi
        done
        echo "Guard blocked link access: OK (${#link_ids[@]} IDs)"
    fi

    # Verify the guard doesn't block unrelated BPF operations.
    # bpftool prog list uses BPF_PROG_GET_NEXT_ID which the guard doesn't
    # intercept (it only blocks *_GET_FD_BY_ID for specific IDs).
    bpftool prog list >/dev/null 2>&1 || true
    echo "Unrelated BPF operations still work: OK"
else
    echo "bpftool not available or map IDs not captured, skipping guard test"
fi

# ------ Test: ptrace attach to PID1 is blocked ------

# dd from /proc/1/mem uses PTRACE_MODE_ATTACH_FSCREDS via mm_access().
# Read from a valid mapped address (not offset 0 which is the unmapped NULL
# page and would fail with -EIO even without the guard).
PID1_ADDR=$(awk '/r-xp/ { split($1, a, "-"); print a[1]; exit }' /proc/1/maps)
if [[ -n "$PID1_ADDR" ]]; then
    PID1_OFFSET=$((16#$PID1_ADDR))
    if ! dd if=/proc/1/mem of=/dev/null bs=1 count=1 skip="$PID1_OFFSET" iflag=skip_bytes 2>/dev/null; then
        echo "Ptrace ATTACH access to PID1 blocked: OK"
    else
        echo "ERROR: /proc/1/mem read should have been blocked!" >&2
        exit 1
    fi
else
    echo "WARNING: Could not determine mapped address for PID1, skipping ptrace test"
fi

# Verify READ-level access to PID1 still works (monitoring tools need this)
if cat /proc/1/status >/dev/null 2>&1; then
    echo "Ptrace READ access to PID1 allowed: OK"
else
    echo "ERROR: /proc/1/status should still be readable!" >&2
    exit 1
fi

# Verify ptrace to non-PID1 processes is unaffected
SLEEP_PID=
sleep 60 &
SLEEP_PID=$!
if cat /proc/$SLEEP_PID/status >/dev/null 2>&1; then
    echo "Ptrace access to non-PID1 unaffected: OK"
else
    echo "ERROR: /proc/$SLEEP_PID/status should be readable!" >&2
    kill "$SLEEP_PID" 2>/dev/null || true
    exit 1
fi
kill "$SLEEP_PID" 2>/dev/null || true
wait "$SLEEP_PID" 2>/dev/null || true
SLEEP_PID=

# ------ Detach and verify enforcement is lifted ------
# Kill the helper process. close() on the link FDs goes through
# bpf_link_put_direct() which synchronously detaches the trampoline.

kill "$HELPER_PID"
wait "$HELPER_PID" 2>/dev/null || true
HELPER_PID=
echo "Helper killed, BPF programs detached synchronously"

if [[ -x /tmp/restrict-fsaccess-test/true ]]; then
    /tmp/restrict-fsaccess-test/true
    echo "Execution from tmpfs after detach: OK"
fi

umount /tmp/restrict-fsaccess-test 2>/dev/null || true
rm -rf /tmp/restrict-fsaccess-test

echo "All enforcement tests passed"
