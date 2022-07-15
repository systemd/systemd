#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

if [[ $# -lt 2 ]]; then
    echo "Usage: ${0} TARGET INPUT [GDBSCRIPT]"
    echo "Debug systemd-boot/stub in QEMU."
    echo
    echo "TARGET should point to the EFI binary to be examined inside the"
    echo "build directory (systemd-boot\$ARCH.efi or linux\$arch.efi.stub)."
    echo
    echo "INPUT should point to the QEMU serial output pipe. This is used to"
    echo "extract the location of the symbols. For this to work, QEMU must"
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
    echo "    ./tools/debug-sd-boot.sh ./build/src/boot/efi/systemd-bootx64.efi \\"
    echo "        /tmp/sdboot.out"
    exit 1
fi

binary=$(realpath "${1}")
if [[ "${1}" =~ systemd-boot([[:alnum:]]+).efi ]]; then
    target="systemd-boot"
    symbols=$(realpath "${1%efi}elf")
elif [[ "${1}" =~ linux([[:alnum:]]+).efi.stub ]]; then
    target="systemd-stub"
    symbols=$(realpath "${1%efi.stub}elf.stub")
else
    echo "Cannot detect EFI binary '${1}'."
    exit 1
fi

case "${BASH_REMATCH[1]}" in
    ia32) arch="i386";;
    x64)  arch="i386:x86-64";;
    aa64) arch="aarch64";;
    arm|riscv64) arch="${BASH_REMATCH[1]}";;
    *)
        echo "Unknown EFI arch '${BASH_REMATCH[1]}'."
        exit 1
esac

# system-boot will print out a line like this to inform us where gdb is supposed to
# look for .text and .data section:
#        systemd-boot@0x0,0x0
while read -r line; do
    if [[ "${line}" =~ ${target}@(0x[[:xdigit:]]+),(0x[[:xdigit:]]+) ]]; then
        text="${BASH_REMATCH[1]}"
        data="${BASH_REMATCH[2]}"
        break
    fi
done < "${2}"

if [[ -z "${text}" || -z "${data}" ]]; then
    echo "Could not determine text and data location."
    exit 1
fi

if [[ -z "${3}" ]]; then
    gdb_script=$(mktemp /tmp/debug-sd-boot.XXXXXX.gdb)
    trap 'rm -f "${gdb_script}"' EXIT
else
    gdb_script="${3}"
fi

echo "file ${binary}
add-symbol-file ${symbols} ${text} -s .data ${data}
set architecture ${arch}" > "${gdb_script}"

if [[ -z "${3}" ]]; then
    gdb -x "${gdb_script}" -ex "target remote :1234"
else
    echo "GDB script written to '${gdb_script}'."
fi
