#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

if [[ $# -lt 2 ]]; then
    echo "Usage: ${0} TARGET INPUT [GDBSCRIPT]"
    echo "Debug systemd-boot/stub in QEMU."
    echo
    echo "TARGET should point to the systemd-boot\$ARCH.efi or linux\$arch.efi.stub"
    echo "EFI binary to be examined."
    echo
    echo "INPUT should point to the QEMU serial output pipe. This is used to"
    echo "extract the location of loaded image base. For this to work, QEMU must"
    echo "be run with '-s -serial pipe:PATH'. Note that QEMU will append"
    echo ".in/.out to the path, while this script expects the out pipe directly."
    echo
    echo "If GDBSCRIPT is empty, gdb is run directly attached to the boot"
    echo "loader, otherwise a script is generated in the given path that allows"
    echo "attaching manually like this:"
    echo "    (gdb) source GDBSCRIPT"
    echo "    (gdb) target remote :1234"
    echo
    echo "Example usage:"
    echo "    mkfifo /tmp/sdboot.{in,out}"
    echo "    qemu-system-x86_64 [...] -s -serial pipe:/tmp/sdboot"
    echo "    ./tools/debug-sd-boot.sh ./build/systemd-bootx64.efi /tmp/sdboot.out"
    exit 1
fi

if [[ "${1}" =~ systemd-boot([[:alnum:]]+).efi ]]; then
    target="systemd-boot"
elif [[ "${1}" =~ linux([[:alnum:]]+).efi.stub ]]; then
    target="systemd-stub"
else
    echo "Cannot detect EFI binary '${1}'."
    exit 1
fi

case "${BASH_REMATCH[1]}" in
    aa64) arch="aarch64";;
    arm)  arch="arm";;
    ia32) arch="i386";;
    x64)  arch="i386:x86-64";;
    *)
        echo "Unknown EFI arch '${BASH_REMATCH[1]}'."
        exit 1
esac

image_base=$(llvm-objdump -p ${1} | sed -nEe 's/^ImageBase\s+([[:xdigit:]]+)$/0x\1/p')
if [[ -z "${image_base}" ]]; then
    echo "Could not determine base address of image '${1}'."
    exit 1
fi

# system-boot/stub will print out a line like this to inform us where it was loaded:
#        systemd-boot@0xC0DE
while read -r line; do
    if [[ "${line}" =~ ${target}@(0x[[:xdigit:]]+) ]]; then
        loaded_base="${BASH_REMATCH[1]}"
        break
    fi
done < "${2}"
if [[ -z "${loaded_base}" ]]; then
    echo "Could not determine base address of loaded image."
    exit 1
fi

if [[ -z "${3}" ]]; then
    gdb_script=$(mktemp /tmp/debug-sd-boot.XXXXXX.gdb)
    trap 'rm -f "${gdb_script}"' EXIT
else
    gdb_script="${3}"
fi

# symbol-file wants a relative offset to apply to all section VMAs. Therefore we have to
# subtract the image base from the reported loaded base to land at the right address.
echo "symbol-file ${1} -o ${loaded_base}-${image_base}
set architecture ${arch}" > "${gdb_script}"

if [[ -z "${3}" ]]; then
    ${GDB:-gdb} -x "${gdb_script}" -ex "target remote :1234"
else
    echo "GDB script written to '${gdb_script}'."
fi
