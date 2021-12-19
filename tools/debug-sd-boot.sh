#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -e

usage() {
    echo "Usage: ${0} OPTIONS [-- QEMU_OPTIONS]"
    echo "Run systemd-boot in QEMU with optional gdb debugging."
    echo "See HACKING.md for example usage."
    echo ""
    echo "Options:"
    echo "  -h --help             Show this help"
    echo "  -b --builddir=PATH    Build directory to look for debug files"
    echo "  -c --efi-code=PATH    Path to OVMF_CODE.fd"
    echo "  -v --efi-vars=PATH    Path to OVMF_VARS.fd (read-write copy)"
    echo "  -i --image=PATH       Path to EFI partition folder/image"
    echo "  -r --run              Just run QEMU"
    echo "  -g --gdb              Run QEMU and start gdb"
    echo "  -G --gdb-script=PATH  Run QEMU and create remote gdb script in PATH"
    echo "  -s --stub             Target systemd-stub for debugging"
}

if ! parsed=$(getopt \
        --options=hb:c:v:i:rgG:s \
        --longoptions=help,builddir:,efi-code:,efi-vars:,image:,run,gdb,gdb-script:,stub \
        --name "${0}" \
        -- \
        "${@}"); then
    usage
    exit 1
fi

eval set -- "${parsed}"

mode=run
builddir=build
target=boot

while true; do
    case "${1}" in
        -b|--builddir)
            builddir=$2
            shift 2
            ;;
        -c|--efi-code)
            efi_code=$2
            shift 2
            ;;
        -v|--efi-vars)
            efi_vars=$2
            shift 2
            ;;
        -i|--image)
            image=$2
            shift 2
            ;;
        -r|--run)
            mode=run
            shift
            ;;
        -g|--gdb)
            mode=gdb
            shift
            ;;
        -G|--gdb-script)
            mode=gdb-script
            gdb_script=$2
            shift 2
            ;;
        -s|--stub)
            target=stub
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unhandled option '${1}'."
            exit 1
            ;;
    esac
done

if [[ ! -e "${image}" ]]; then
    echo "Need to provide EFI folder/image to boot."
    exit 1
fi

if [[ ! -d "${builddir}" ]]; then
    echo "Cannot find build dir '${builddir}'."
    exit 1
fi

builddir=$(realpath -q "${builddir}/src/boot/efi")
if [[ -f "${builddir}/systemd-bootx64.efi" ]]; then
    arch="x86_64"
    efi_arch="x64"
    gdb_arch="i386:x86-64:intel"
    efi_code_name="OVMF_CODE.fd"
    efi_vars_name="OVMF_VARS.fd"
    efi_code_paths=(
        "/usr/share/edk2-ovmf/x64" # Arch
        "/usr/share/edk2/ovmf"     # Fedora
        "/usr/share/OVMF"
    )
else
    echo "Could not find systemd-boot binaries in build dir. Did you forget to"
    echo "run ninja? Note that this script currently only supports x86_64."
    exit 1
fi

if [[ -z "${efi_code}" ]]; then
    for path in "${efi_code_paths[@]}"; do
        efi_code="${path}/${efi_code_name}"
        if [[ -f "${efi_code}" ]]; then
            break
        fi
    done
fi

if [[ ! -f "${efi_code}" ]]; then
    echo "Could not find ${efi_code_name}."
    exit 1
fi

if [[ -z "${efi_vars}" ]]; then
    efi_vars="$(dirname "${efi_code}")/${efi_vars_name}"
fi

if [[ ! -f "${efi_vars}" ]]; then
    echo "Could not find ${efi_vars_name}."
    exit 1
elif [[ ! -w "${efi_vars}" ]]; then
    echo "${efi_vars} is read-only. Changes to EFI vars will be lost on QEMU exit."
    efi_vars_ro="readonly=on,"
fi

case "${mode}" in
    run)
        wrapper="exec"
        qemu_args=()
        ;;
    gdb|gdb-script)
        temp=$(mktemp -d /tmp/systemd-boot-XXXXXX)
        trap 'rm -rf "${temp}"' EXIT
        mkfifo "${temp}/pipe."{in,out}

        # Use systemd-run or otherwise gdb ends up passing Ctrl+C to QEMU
        # instead of giving us a prompt.
        wrapper="systemd-run --user"
        qemu_args=("-s" "-serial" "pipe:${temp}/pipe")
        ;;
    *)
        echo "Unhandled mode '${mode}'."
        exit 1
        ;;
esac

# Leverage QEMU automatically turning a directory into a suitable fat ramdisk.
if [[ -d "${image}" ]]; then
    image="fat:rw:${image}"
fi

${wrapper} qemu-system-${arch} \
    -drive if=pflash,format=raw,readonly=on,file="${efi_code}" \
    -drive if=pflash,format=raw,${efi_vars_ro}file="${efi_vars}" \
    -drive format=raw,file="${image}" \
    -net none \
    "${qemu_args[@]}" \
    "${@}"

if [[ "${mode}" == "run" ]]; then
    # We did exec, so this is just in case…
    exit 0
fi

# system-boot will print out a line like this to inform us where gdb is supposed to
# look for .text and .data section:
#        systemd-boot@0x0,0x0
while read -r line; do
    if [[ "${line}" =~ ${target}@(0x[[:xdigit:]]+),(0x[[:xdigit:]]+) ]]; then
        text="${BASH_REMATCH[1]}"
        data="${BASH_REMATCH[2]}"
        break
    fi
done < "${temp}/pipe.out"

case "${target}" in
    boot)
        target="${builddir}/systemd-boot${efi_arch}.efi"
        symbols="${builddir}/systemd_boot.so"
        ;;
    stub)
        target="${builddir}/linux${efi_arch}.efi.stub"
        symbols="${builddir}/linux${efi_arch}.elf.stub"
        ;;
    *)
        echo "Unhandled target '${target}'."
        exit 1
        ;;
esac

gdb_script=${gdb_script:-"${temp}/gdb"}
echo "file ${target}" > "${gdb_script}"
echo "add-symbol-file ${symbols} ${text} -s .data ${data}" >> "${gdb_script}"
echo "set architecture ${gdb_arch}" >> "${gdb_script}"

case "${mode}" in
    gdb)
        gdb -x "${gdb_script}" -ex "target remote :1234"
        ;;
    gdb-script)
        echo "GDB script written to '${gdb_script}'."
        ;;
esac
