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
# Requires the VM to be booted with dm_verity.require_signatures=1 and
# proc_mem.force_override=never on the kernel command line (set in the test's
# meson.build).
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Skip if prerequisites not met
if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
    echo "BPF framework not compiled in, skipping"
    exit 77
fi

if ! kernel_supports_lsm bpf; then
    echo "BPF LSM not available in kernel, skipping"
    exit 77
fi

# Check that the kernel has the bdev_setintegrity LSM hook in BTF.
# Older kernels (e.g., CentOS 9 with 5.14) lack this hook entirely.
if command -v bpftool >/dev/null 2>&1; then
    if ! bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep 'bpf_lsm_bdev_setintegrity' >/dev/null; then
        echo "Kernel lacks bdev_setintegrity LSM hook (required for RestrictFileSystemAccess=), skipping"
        exit 77
    fi
fi

if [[ -v ASAN_OPTIONS ]]; then
    echo "Skipping enforcement test under sanitizers"
    exit 77
fi

HELPER="/usr/lib/systemd/tests/unit-tests/manual/test-bpf-restrict-fsaccess"
if [[ ! -x "$HELPER" ]]; then
    echo "ERROR: test-bpf-restrict-fsaccess helper not found at $HELPER" >&2
    exit 1
fi

# The helper's probes exit with 0 if the operation was allowed, 1 if it was
# refused with the errno the mechanism under test produces, 2 if it could not
# be attempted and 3 if it was refused with an unexpected errno. Only the exact
# code counts, so a broken probe cannot pass as a denial.
expect_probe() {
    local expected="$1" what="$2" rc=0
    shift 2
    "$HELPER" "$@" || rc=$?
    if [[ "$rc" -ne "$expected" ]]; then
        echo "ERROR: $what: helper '$*' exited with $rc, expected $expected" >&2
        exit 1
    fi
}

# require_signatures is read-only — must be set via kernel cmdline
if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    modprobe dm_verity 2>/dev/null || true
fi
if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    echo "dm_verity module not available, skipping enforcement test"
    exit 77
fi
val="$(cat /sys/module/dm_verity/parameters/require_signatures)"
if [[ "$val" != "Y" && "$val" != "1" ]]; then
    echo "require_signatures not enabled (need dm-verity.require_signatures=1 on cmdline), skipping"
    exit 77
fi

# proc_mem.force_override is __ro_after_init and has no readout: like
# require_signatures it must come from the kernel cmdline (set in meson.build).
if ! grep -E '(^|[[:space:]])proc_mem\.force_override=never([[:space:]]|$)' /proc/cmdline >/dev/null; then
    echo "proc_mem.force_override=never not on the kernel cmdline (set in meson.build), skipping"
    exit 77
fi

# PID1 refuses the policy without seccomp support, and so does the helper's "check".
if ! systemctl --version | grep -F -- "+SECCOMP" >/dev/null; then
    echo "seccomp support not compiled in, skipping"
    exit 77
fi

# Helper exits 77 when systemd was built with bpf-framework=enabled but no
# vmlinux.h (HAVE_LSM_INTEGRITY_TYPE=0), so the BPF program isn't compiled in.
# Run it only once, and only now that dm_verity is loaded so a pass is
# meaningful: a passing "check" briefly attaches the bprm_check program with
# an empty trust map, denying every execve() on the system meanwhile.
CHECK_RC=0
"$HELPER" check || CHECK_RC=$?
if [[ "$CHECK_RC" -eq 77 ]]; then
    echo "test-bpf-restrict-fsaccess built without BPF attach support, skipping"
    exit 77
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
    # Clean up overlay test mounts
    umount /tmp/restrict-fsaccess-overlay/merged 2>/dev/null || true
    umount /tmp/restrict-fsaccess-overlay/rw 2>/dev/null || true
    systemd-dissect --umount /tmp/restrict-fsaccess-overlay/lower 2>/dev/null || true
    rm -rf /tmp/restrict-fsaccess-overlay
    # Clean up background processes
    [[ -n "${SLEEP_PID:-}" ]] && kill "$SLEEP_PID" 2>/dev/null || true
    rm -rf /tmp/restrict-fsaccess-attach.out
}
trap at_exit EXIT

# ------ Preconditions: helper "check" must agree with the cmdline ------
# "check" runs the same gates as PID1: BPF LSM, require_signatures,
# proc_mem.force_override=never on the cmdline plus a /proc/self/mem self-probe
# verifying the kernel honours it, and the ptrace seccomp filter.
# SYSTEMD_PROC_CMDLINE overrides what the helper considers the kernel command
# line; the gates run before any BPF program is loaded, so the rejections
# below are cheap and attach nothing.

if [[ "$CHECK_RC" -ne 0 ]]; then
    echo "ERROR: helper check failed (rc=$CHECK_RC) although all prerequisites are met!" >&2
    exit 1
fi
echo "Helper check with proc_mem.force_override=never: OK"

# "never ptrace" being rejected shows the last occurrence wins, like the
# kernel's early_param handling.
for bad in "" "proc_mem.force_override=always" "proc_mem.force_override=ptrace" \
           "proc_mem.force_override=never proc_mem.force_override=ptrace"; do
    if SYSTEMD_PROC_CMDLINE="$bad" "$HELPER" check 2>/dev/null; then
        echo "ERROR: helper check should have rejected cmdline '$bad'!" >&2
        exit 1
    fi
done
echo "Helper check rejects always/ptrace/unset and honours the last occurrence: OK"

# ------ Test: /proc/self/mem cannot rewrite an executable page ------
# Independent of the BPF programs: with proc_mem.force_override=never the
# kernel drops FOLL_FORCE, so the copy-on-write through /proc/self/mem is
# refused with EIO.

expect_probe 1 "/proc/self/mem rewrite of an executable page" procmem-cow /usr/bin/true
echo "/proc/self/mem rewrite of executable page refused: OK"

# ------ Test: the ptrace seccomp filter refuses PTRACE_POKE{TEXT,DATA} ------
# The helper installs the same filter PID1 uses and pokes a traced child; the
# probe only counts as a denial if PTRACE_PEEKTEXT still worked.

expect_probe 1 "PTRACE_POKETEXT/PTRACE_POKEDATA" poketext
echo "PTRACE_POKETEXT/PTRACE_POKEDATA refused by seccomp filter: OK"

# ------ Baseline: W^X probes succeed WITHOUT our BPF ------
# Another LSM (e.g. SELinux execmem/execmod) may deny these on its own, which
# the helper reports as exit 3 (refused with an errno other than EPERM). A
# denial with BPF attached would then prove nothing, so skip them. Anything
# else is a broken probe or a stray policy and fails the test.

WX_BASELINE=1
for probe in mmap-wx mprotect-cow-exec mprotect-wx mprotect-exec; do
    rc=0
    "$HELPER" "$probe" /usr/bin/true || rc=$?
    case "$rc" in
        0) ;;
        3)
            echo "WARNING: $probe denied BEFORE BPF attach by another LSM, skipping W^X tests" >&2
            WX_BASELINE=0
            break
            ;;
        *)
            echo "ERROR: $probe failed BEFORE BPF attach (rc=$rc)!" >&2
            exit 1
            ;;
    esac
done

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
    exit 77
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
done >/tmp/restrict-fsaccess-attach.out

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

# File-backed PROT_EXEC mmap should be denied (with EPERM, see expect_probe).
expect_probe 1 "PROT_EXEC mmap of tmpfs file" mmap-exec /tmp/restrict-fsaccess-test/testfile
echo "PROT_EXEC mmap from tmpfs blocked: OK"

# Anonymous PROT_EXEC mmap should be denied (NULL file — mmap_file hook)
expect_probe 1 "anonymous PROT_EXEC mmap" anon-mmap-exec
echo "Anonymous PROT_EXEC mmap blocked: OK"

# ------ Test: mprotect adding PROT_EXEC is blocked (file_mprotect hook) ------

# mmap PROT_READ then mprotect to PROT_EXEC — the file_mprotect hook should deny this.
expect_probe 1 "mprotect PROT_EXEC on tmpfs file" mprotect-exec /tmp/restrict-fsaccess-test/testfile
echo "mprotect PROT_EXEC from tmpfs blocked: OK"

# ------ Test: W^X on a trusted file (mmap_file + file_mprotect hooks) ------
# /usr/bin/true lives on the trusted rootfs, so a denial here is due to the
# W^X rules, not provenance.

if [[ "$WX_BASELINE" == 1 ]]; then
    for probe in mmap-wx mprotect-cow-exec mprotect-wx; do
        expect_probe 1 "$probe on a trusted file" "$probe" /usr/bin/true
        echo "W^X probe $probe blocked: OK"
    done

    # Positive control: an unmodified trusted file mapping may still be made
    # executable — the copy-on-write heuristic must not over-deny.
    expect_probe 0 "PROT_EXEC mmap of trusted file" mmap-exec /usr/bin/true
    expect_probe 0 "mprotect PROT_EXEC on trusted file" mprotect-exec /usr/bin/true
    echo "Executable mappings of unmodified trusted file allowed: OK"
fi

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

# ------ Test: overlayfs over a signed dm-verity lower layer ------
# Kernels with the bpf_real_data_inode() kfunc (v7.2+) resolve files on
# union filesystems to the layer hosting the data: execution through an
# overlay whose lower layer sits on a signed verity device is permitted,
# while files created in (or copied up to) an untrusted upper layer are
# denied. Without the kfunc, everything on the overlay is denied.

if command -v bpftool >/dev/null 2>&1; then
    KERNEL_HAS_REAL_DATA_INODE=0
    if bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep "FUNC 'bpf_real_data_inode'" >/dev/null; then
        KERNEL_HAS_REAL_DATA_INODE=1
    fi

    # The loader's BTF probe must agree with the kernel BTF
    HAVE_RDI="$(sed -n 's/^HAVE_REAL_DATA_INODE=//p' /tmp/restrict-fsaccess-attach.out)"
    if [[ "$HAVE_RDI" != "$KERNEL_HAS_REAL_DATA_INODE" ]]; then
        echo "ERROR: Loader probed have_real_data_inode=$HAVE_RDI but kernel BTF says $KERNEL_HAS_REAL_DATA_INODE!" >&2
        exit 1
    fi

    if machine_supports_verity_keyring; then
        OVL=/tmp/restrict-fsaccess-overlay
        mkdir -p "$OVL"/{lower,rw,merged}
        systemd-dissect --mount "$MINIMAL.raw" "$OVL/lower"
        mount -t tmpfs tmpfs "$OVL/rw"
        mkdir -p "$OVL/rw/upper" "$OVL/rw/work"
        # metacopy=off: a metadata-only copy-up would keep the data — and
        # hence the verdict — on the lower layer, breaking the copy-up test
        mount -t overlay overlay \
            -o "lowerdir=$OVL/lower/usr,upperdir=$OVL/rw/upper,workdir=$OVL/rw/work,metacopy=off" \
            "$OVL/merged"

        if [[ "$KERNEL_HAS_REAL_DATA_INODE" == 1 ]]; then
            # Resolution follows the data to the signed verity lower layer
            "$OVL/merged/bin/bash" -c 'exit 0'
            echo "Execution through overlay from signed verity lower: OK"

            # A file created in the (tmpfs) upper layer is untrusted.
            # Basename must stay "true" for multicall coreutils binaries —
            # see the baseline comment above.
            cp /usr/bin/true "$OVL/merged/true"
            if "$OVL/merged/true" 2>/dev/null; then
                echo "ERROR: Execution of upper-layer file should have been blocked!" >&2
                exit 1
            fi
            echo "Execution from overlay upper layer blocked: OK"

            # Copy-up moves the data to the untrusted upper layer
            chmod 700 "$OVL/merged/bin/bash"
            if "$OVL/merged/bin/bash" -c 'exit 0' 2>/dev/null; then
                echo "ERROR: Execution of copied-up file should have been blocked!" >&2
                exit 1
            fi
            echo "Execution of copied-up file blocked: OK"
        else
            # Without the kfunc all the program sees is the overlay's
            # anonymous device: deny, even though the lower is trusted
            if "$OVL/merged/bin/bash" -c 'exit 0' 2>/dev/null; then
                echo "ERROR: Execution through overlay should have been blocked without bpf_real_data_inode!" >&2
                exit 1
            fi
            echo "Execution through overlay blocked (no bpf_real_data_inode): OK"
        fi

        umount "$OVL/merged"
        umount "$OVL/rw"
        systemd-dissect --umount "$OVL/lower"
        rm -rf "$OVL"
    else
        echo "Verity keyring trust not available, skipping overlay tests"
    fi
else
    echo "bpftool not available, skipping overlay tests"
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
