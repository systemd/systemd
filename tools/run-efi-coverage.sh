#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Run the instrumented systemd-boot / systemd-stub under OVMF in QEMU and
# capture the .gcda counter files the firmware binaries write to the ESP,
# producing an lcov tracefile per scenario that can be merged into the
# regular coverage report (see "Combine coverage reports" in
# .github/workflows/coverage.yml, which picks up TEST-*.coverage-info).
#
# The build must be configured with -Defi-coverage=true (the efi-coverage
# meson option, default off): the EFI binaries are then built with gcov
# instrumentation and flush their counters to the ESP's /loader/ directory
# (volume root as fallback) at exit, see src/boot/efi-gcov.c.
#
# Scenarios:
#   uki     boot a UKI (linux<arch>.efi.stub + kernel + initrd) - covers the
#           stub side (stub.c, linux.c, splash.c, boot-secret.c, ...)
#   sd-boot boot the boot manager (systemd-boot<arch>.efi) without any boot
#           entries - covers the manager side (boot.c, bootspec.c, ...)
#   both    run both scenarios (default)
#
# The kernel does not have to fully boot: the stub flushes its counters right
# before the kernel handoff, so the QEMU process is killed after the boot.
#
# Usage:
#   tools/run-efi-coverage.sh [uki|sd-boot|both] [options]
#
# Options:
#   --build DIR         meson build directory (default: <repo>/build)
#   --kernel FILE       kernel image for the UKI (default: $MKOSI_OUTPUT/image.vmlinuz)
#   --initrd FILE       initrd for the UKI (default: $MKOSI_OUTPUT/initrd.cpio.zst)
#   --mkosi-output DIR  directory holding image.vmlinuz + initrd (default: $BUILD/mkosi.output)
#   --ovmf DIR          OVMF directory (default: auto-detected)
#   --workdir DIR       scratch directory (default: mktemp -d, removed on exit)
#   --keep-workdir      do not remove the scratch directory on exit
#   --seconds N         per-boot QEMU timeout (default: 120)
#   --mem N             guest RAM in MiB (default: 2048 for uki, 512 for sd-boot)
#   --output DIR        tracefile directory (default: $BUILD/test/coverage)
#   --help              this text

set -euo pipefail

usage() { sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

mode=both
BUILD=
KERNEL=
INITRD=
MKOSI_OUTPUT=
OVMF=
WORKDIR=
KEEP_WORKDIR=0
NO_LCOV=0
SECONDS_BOOT=120
MEM=
OUTPUT=

while [ $# -gt 0 ]; do
    case $1 in
    uki|sd-boot|both)    mode=$1 ;;
    --build)            BUILD=$2; shift ;;
    --kernel)           KERNEL=$2; shift ;;
    --initrd)           INITRD=$2; shift ;;
    --mkosi-output)     MKOSI_OUTPUT=$2; shift ;;
    --ovmf)             OVMF=$2; shift ;;
    --workdir)          WORKDIR=$2; shift ;;
    --keep-workdir)     KEEP_WORKDIR=1 ;;
    --seconds)          SECONDS_BOOT=$2; shift ;;
    --mem)              MEM=$2; shift ;;
    --output)           OUTPUT=$2; shift ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

# User-supplied paths are resolved before the first cd, so that relative
# values keep working after the script changes directory (ukify, assemble,
# distribute, clean and the .ok check all run elsewhere). -m keeps paths
# that do not exist yet resolvable: the existence checks below still
# report them in die style (a failing bare realpath would abort the
# script here, where errexit is in effect).
[ -n "$BUILD" ] && BUILD=$(realpath -m "$BUILD")
[ -n "$KERNEL" ] && KERNEL=$(realpath -m "$KERNEL")
[ -n "$INITRD" ] && INITRD=$(realpath -m "$INITRD")
[ -n "$MKOSI_OUTPUT" ] && MKOSI_OUTPUT=$(realpath -m "$MKOSI_OUTPUT")
[ -n "$OVMF" ] && OVMF=$(realpath -m "$OVMF")
[ -n "$WORKDIR" ] && WORKDIR=$(realpath -m "$WORKDIR")
[ -n "$OUTPUT" ] && OUTPUT=$(realpath -m "$OUTPUT")

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

[ -n "$BUILD" ] || BUILD="$ROOT/build"
[ -n "$OUTPUT" ] || OUTPUT="$BUILD/test/coverage"

die() { echo "run-efi-coverage: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null || die "required tool '$1' not found (install the corresponding package)"; }

# -- inputs -------------------------------------------------------------

# Positive list of the supported EFI architectures, in preference order:
# the first one the build provides is used. Adding an architecture is more
# than a name: the qemu target mapping below has to learn it, and OVMF
# firmware, a QEMU machine type and a matching kernel/initrd have to follow.
SUPPORTED_EFI_ARCHS=x64
[ -d "$BUILD" ] || die "build directory '$BUILD' not found (meson setup first)"
# Detect which of the supported architectures this build provides.
EFI_ARCH=
for a in $SUPPORTED_EFI_ARCHS; do
    [ -f "$BUILD/src/boot/linux$a.efi.stub" ] && { EFI_ARCH=$a; break; }
done
if [ -z "$EFI_ARCH" ]; then
    other=
    for stub in "$BUILD"/src/boot/linux*.efi.stub; do
        [ -e "$stub" ] || continue
        o=${stub##*/linux}; o=${o%.efi.stub}
        case " $SUPPORTED_EFI_ARCHS " in *" $o "*) continue ;; esac
        other=${other:+$other }$o
    done
    if [ -n "$other" ]; then
        die "the build is for '$other', but this runner only supports: $SUPPORTED_EFI_ARCHS"
    fi
    die "instrumented stub not found: configure the build with -Defi-coverage=true and rebuild"
fi
[ -f "$BUILD/src/boot/linux$EFI_ARCH.elf.stub.p/stub.c.gcno" ] || \
    die "no .gcno files in $BUILD/src/boot/linux$EFI_ARCH.elf.stub.p: is -Defi-coverage=true set?"
[ -f "$BUILD/src/boot/systemd-boot$EFI_ARCH.elf.p/boot.c.gcno" ] || \
    die "no .gcno files in $BUILD/src/boot/systemd-boot$EFI_ARCH.elf.p: is -Defi-coverage=true set?"

# qemu target names differ from meson's efi_arch names
case $EFI_ARCH in
    x64)     QEMU_TARGET=x86_64 ;;
    ia32)    QEMU_TARGET=i386 ;;
    aa64)    QEMU_TARGET=aarch64 ;;
    riscv64) QEMU_TARGET=riscv64 ;;
    *)       die "no qemu target for EFI arch '$EFI_ARCH'" ;;
esac
for t in "qemu-system-$QEMU_TARGET" mcopy mdir mmd mkfs.vfat python3; do have "$t"; done

# OVMF: the plain (non-secure-boot) CODE/VARS pair, 4M chips first. The
# distro layouts differ: Fedora ships qcow2 files under
# /usr/share/edk2/ovmf, Arch raw .fd under /usr/share/edk2/x64 (lowercase
# 4m in the file names) and Debian raw .fd under /usr/share/OVMF.
OVMF_CODE=
OVMF_VARS=
if [ -z "$OVMF" ]; then
    for dir in /usr/share/edk2/ovmf /usr/share/edk2/x64 /usr/share/OVMF; do
        for f in OVMF_CODE_4M.qcow2 OVMF_CODE.4m.fd OVMF_CODE_4M.fd OVMF_CODE.qcow2 OVMF_CODE.fd; do
            if [ -f "$dir/$f" ]; then
                OVMF=$dir
                OVMF_CODE=$dir/$f
                break 2
            fi
        done
    done
    [ -n "$OVMF" ] || die "OVMF firmware not found (install the edk2-ovmf / ovmf package)"
fi
if [ -z "$OVMF_CODE" ]; then
    for f in OVMF_CODE_4M.qcow2 OVMF_CODE.4m.fd OVMF_CODE_4M.fd OVMF_CODE.qcow2 OVMF_CODE.fd; do
        [ -f "$OVMF/$f" ] && OVMF_CODE="$OVMF/$f" && break
    done
fi
[ -n "$OVMF_CODE" ] || die "OVMF CODE file not found in $OVMF"
for f in OVMF_VARS_4M.qcow2 OVMF_VARS.4m.fd OVMF_VARS_4M.fd OVMF_VARS.qcow2 OVMF_VARS.fd; do
    [ -f "$OVMF/$f" ] && OVMF_VARS="$OVMF/$f" && break
done
[ -n "$OVMF_VARS" ] || die "OVMF VARS file not found in $OVMF"
# QEMU knows no ".fd" block driver: raw .fd chips are format=raw
case $OVMF_CODE in
    *.qcow2) OVMF_CODE_FMT=qcow2 ;;
    *)       OVMF_CODE_FMT=raw ;;
esac
case $OVMF_VARS in
    *.qcow2) OVMF_VARS_FMT=qcow2 ;;
    *)       OVMF_VARS_FMT=raw ;;
esac

if [ "$mode" = uki ] || [ "$mode" = both ]; then
    [ -n "$MKOSI_OUTPUT" ] || MKOSI_OUTPUT="$BUILD/mkosi.output"
    [ -n "$KERNEL" ] || KERNEL="$MKOSI_OUTPUT/image.vmlinuz"
    [ -n "$INITRD" ] || INITRD="$MKOSI_OUTPUT/initrd.cpio.zst"
    [ -f "$KERNEL" ] || die "kernel image not found: $KERNEL (pass --kernel, or build the mkosi target first)"
    [ -f "$INITRD" ] || die "initrd not found: $INITRD (pass --initrd)"
fi

# -- scratch --------------------------------------------------------------

WORKDIR_SELF=0
[ -n "$WORKDIR" ] || { WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/efi-coverage.XXXXXX"); WORKDIR_SELF=1; }
mkdir -p "$WORKDIR" "$OUTPUT"
echo "workdir: $WORKDIR (keep=$KEEP_WORKDIR, arch=$EFI_ARCH)"
# drop state from an earlier run in this directory: a stale .ok would make the
# cleanup below remove the directory as if *this* run had succeeded, and stale
# gcda-* would be redistributed as if they came from this boot
rm -f "$WORKDIR/.ok"
rm -rf -- "$WORKDIR"/gcda-uki "$WORKDIR"/gcda-sd-boot
# remove .gcda counter files from the build tree: they are runtime byproducts
# of earlier boots; left behind, the next capture picks them up and fails
# with a "stamp mismatch" as soon as the binaries were recompiled in the
# meantime
clean() {
    find "$BUILD/src/boot" -name "*.gcda" -delete 2>/dev/null || true
}
# keep the scratch dir (serial logs, disk images) unless the run succeeded;
# a user-provided workdir is never removed, only one this run created
cleanup() {
    if [ "$WORKDIR_SELF" = 0 ]; then
        echo "workdir kept (user-provided): $WORKDIR"
    elif [ "$KEEP_WORKDIR" = 1 ] || [ ! -f "$WORKDIR/.ok" ]; then
        echo "workdir kept: $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
    # keep the counter files in the build tree when the capture could not
    # run (no lcov), so they can be processed manually
    [ "$NO_LCOV" = 1 ] || clean
}
trap cleanup EXIT
cd "$WORKDIR"

# GPT if sgdisk is available (OVMF creates partition objects only for GPT
# disks, which the stub needs to find the ESP), MBR as fallback. The
# coverage dump goes to the volume's /loader/ directory either way
# (efi-gcov.c does not consult the partition table).
HAVE_SGDISK=0
command -v sgdisk >/dev/null && HAVE_SGDISK=1

# assemble <ukifile> <part-sectors> <out-disk>
assemble() {
    local uki=$1 part_sectors=$2 out=$3
    dd if=/dev/zero of=part.img bs=512 count="$part_sectors" status=none
    mkfs.vfat -n ESP part.img >/dev/null
    mmd -i part.img ::/EFI
    mmd -i part.img ::/EFI/BOOT
    # the UEFI spec's default boot file is per-arch and all-caps
    # (BOOTX64.EFI, BOOTIA32.EFI, BOOTAA64.EFI, ...); meson's efi_arch
    # names are lowercase, so uppercase the suffix to match the spec
    mcopy -i part.img "$uki" "::/EFI/BOOT/BOOT${EFI_ARCH^^}.EFI"
    if [ "$HAVE_SGDISK" = 1 ]; then
        local disk_sectors=$((2048 + part_sectors + 34))
        dd if=/dev/zero of="$out" bs=512 count="$disk_sectors" status=none
        sgdisk -Z "$out" >/dev/null
        sgdisk -n 1:2048:$((2048 + part_sectors - 1)) -t 1:ef00 -c 1:ESP "$out" >/dev/null
        dd if=part.img of="$out" bs=512 seek=2048 conv=notrunc status=none
    else
        # MBR: 0xEF entry at LBA 2048, partition spliced after zero padding
        python3 - "$part_sectors" "$out" <<'EOF'
import struct, sys
start, count, out = 2048, int(sys.argv[1]), sys.argv[2]
mbr = bytearray(512)
mbr[510:512] = b'\x55\xAA'
mbr[0x1BE:0x1BE+16] = bytes([0x80, 0x00, 0x00, 0x01, 0xEF, 0xFF, 0xFF, 0x3F]) + struct.pack('<II', start, count)
off = start * 512
part = open('part.img', 'rb').read()
assert len(part) == count * 512
open(out, 'wb').write(bytes(mbr) + b'\0' * (off - 512) + part)
EOF
    fi
    rm -f part.img
}

# recover <disk> <dir>: slice the 1 MiB-aligned partition off the disk image
# and mcopy the .gcda files the firmware wrote to the ESP. efi-gcov.c always
# writes to the volume's /loader/ directory (it does not consult the
# partition table); the volume root listing is a defensive fallback.
recover() {
    local disk=$1 dir=$2 src="::/" names f count=0
    mkdir -p "$dir"
    dd if="$disk" of=part_after.img bs=512 skip=2048 status=none
    names=$(mdir -i part_after.img -/ ::/loader 2>/dev/null | awk '{for (i = NF; i >= 1; i--) if ($i ~ /\.gcda$/) print $i}' || true)
    [ -n "$names" ] && src="::/loader/"
    if [ -z "$names" ]; then
        names=$(mdir -i part_after.img -/ ::/ 2>/dev/null | awk '{for (i = NF; i >= 1; i--) if ($i ~ /\.gcda$/) print $i}' || true)
    fi
    for f in $names; do
        if mcopy -i part_after.img "${src}$f" "$dir/" 2>/dev/null; then
            count=$((count + 1))
        fi
    done
    echo "recovered $count .gcda files"
    [ "$count" -ge 1 ]
}

boot() {
    local name=$1 mem=$2 disk=$3
    cp -f "$OVMF_VARS" "vars.$name"
    echo "== boot $name ($disk, OVMF $(basename "$OVMF_CODE") + $(basename "$OVMF_VARS")):"
    timeout "$SECONDS_BOOT" "qemu-system-$QEMU_TARGET" \
        -M q35 -cpu max -m "$mem" -smp 1 \
        -drive "if=pflash,format=$OVMF_CODE_FMT,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,format=$OVMF_VARS_FMT,file=vars.$name" \
        -drive if=ide,format=raw,file="$disk" \
        -display none -no-reboot -serial file:"serial.$name".log -monitor none \
        -d guest_errors -D "qemu-guest-errors.$name".log || true
}

# distribute <gcda-dir>: place each recovered .gcda file next to the .gcno
# of the object that wrote it, so that geninfo can pair them up. Every
# source has exactly one .gcno in this layout (the libefi sources are
# compiled once into the static library, the rest into a single binary
# each), so the match is by basename; the identifier the .gcda header
# records of its notes file is checked against the .gcno as a consistency
# guard (it fails if the tree was recompiled without the matching notes).
# The run fails if a single .gcda cannot be placed: a silent drop here
# would show up only as a coverage gap in the report.
distribute() {
    local dir=$1
    clean
    python3 - "$dir" "$BUILD/src/boot" <<'EOF'
import os, shutil, struct, sys
gdadir, bootdir = sys.argv[1], sys.argv[2]

def identifier(path):
        h = open(path, 'rb').read(64)
        ln = struct.unpack('<I', h[36:40])[0]
        if 8 <= ln <= 32:
                return h[40:40 + ln]
        return None

names = sorted(n for n in os.listdir(gdadir) if n.endswith('.gcda'))
placed = 0
failed = []
for name in names:
        src = os.path.join(gdadir, name)
        base = name[:-5]
        cands = [d for d in os.listdir(bootdir)
                 if os.path.isfile(os.path.join(bootdir, d, base + '.gcno'))]
        if not cands:
                print(f"error: no notes file for {name}", file=sys.stderr)
                failed.append(name)
                continue
        ident = identifier(src)
        hit = None
        for d in cands:
                gcno = os.path.join(bootdir, d, base + '.gcno')
                if ident is None or ident in open(gcno, 'rb').read(4096):
                        hit = d
                        break
        if hit is None:
                print(f"error: notes file for {name} does not match the "
                      "counter file, did you recompile without relinking? "
                      "(run: meson compile in the build directory)", file=sys.stderr)
                failed.append(name)
                continue
        shutil.copyfile(src, os.path.join(bootdir, hit, name))
        placed += 1
print(f"distributed {placed}/{len(names)} .gcda files into {bootdir}")
if failed:
        sys.exit(1)
EOF
}

# capture <name>: generate the lcov tracefile from the .gcda files
# distributed into the meson .p directories above
capture() {
    local name=$1
    local out="$OUTPUT/TEST-efi-$name.coverage-info"
    if ! command -v lcov >/dev/null; then
        NO_LCOV=1
        echo "lcov not found: the .gcda files are kept in the build tree (and in $WORKDIR) - run lcov --capture manually"
        return 1
    fi
    if ! lcov --directory "$BUILD/src/boot" --capture \
        --exclude "*.gperf" \
        --output-file "$out" \
        --ignore-errors source,gcov,graph,inconsistent,empty,unused \
        --quiet >/dev/null 2>"$WORKDIR/lcov-$name.log"; then
        echo "lcov failed for scenario '$name', log: $WORKDIR/lcov-$name.log" >&2
        sed -n '1,20p' "$WORKDIR/lcov-$name.log" >&2
        return 1
    fi
    echo "tracefile: $out"
}

# -- scenarios ------------------------------------------------------------

if [ "$mode" = uki ] || [ "$mode" = both ]; then
    # 512 MiB ESP: the .initrd section of a full distro image can be ~130 MiB.
    # No "quiet" in the cmdline: the kernel version banner is a KERN_INFO
    # line and the serial check below relies on seeing it.
    python3 "$ROOT/src/ukify/ukify.py" build \
        --stub "$BUILD/src/boot/linux$EFI_ARCH.efi.stub" \
        --linux "$KERNEL" \
        --initrd "$INITRD" \
        --cmdline "console=ttyS0" \
        --os-release @/etc/os-release \
        --uname efi-coverage \
        -o uki.efi
    assemble uki.efi 1048576 disk-uki.img
    mem=${MEM:-2048}
    boot uki "$mem" disk-uki.img
    # the kernel line is the success heuristic; the .gcda check is decisive
    sed -e 's/\x1b\[[0-9;]*[a-zA-Z]//g' serial.uki.log | grep -a "Linux version" \
        || echo "warning: no kernel start detected in serial.uki.log"
    recover disk-uki.img gcda-uki
    distribute gcda-uki
    capture uki
fi

if [ "$mode" = sd-boot ] || [ "$mode" = both ]; then
    # 64 MiB ESP is enough for the boot manager. Without loader entries of
    # its own the menu shows only "Reboot Into Firmware Interface"
    # (auto-firmware is on by default), which the manager auto-boots after
    # the 10s countdown; that path flushes the gcov counters before the
    # warm reset that ends the boot (qemu runs with -no-reboot)
    assemble "$BUILD/src/boot/systemd-boot$EFI_ARCH.efi" 131072 disk-sdboot.img
    mem=${MEM:-512}
    boot sd-boot "$mem" disk-sdboot.img
    recover disk-sdboot.img gcda-sd-boot
    distribute gcda-sd-boot
    capture sd-boot
fi

touch "$WORKDIR/.ok"
echo "run-efi-coverage: done"
