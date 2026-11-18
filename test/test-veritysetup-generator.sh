#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

if [[ -n "${1:-}" ]]; then
    generator=$1
elif [[ -x /usr/lib/systemd/system-generators/systemd-veritysetup-generator ]]; then
    generator=/usr/lib/systemd/system-generators/systemd-veritysetup-generator
elif [[ -x /lib/systemd/system-generators/systemd-veritysetup-generator ]]; then
    generator=/lib/systemd/system-generators/systemd-veritysetup-generator
else
    exit 1
fi

# The first 128 bits of the root hash are the partition UUID of the data partition, and the last 128 bits are
# the partition UUID of the hash partition.
USRHASH=0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210
DATA=/dev/disk/by-partuuid/01234567-89ab-cdef-0123-456789abcdef
HASH=/dev/disk/by-partuuid/fedcba98-7654-3210-fedc-ba9876543210

# Run the generator with the kernel command line in $2, and check that the ExecStart= line of the generated
# systemd-veritysetup@$1.service passes the options in $3 to systemd-veritysetup. The root hash on the kernel
# command line is roothash= for "root" and usrhash= for "usr".
check_unit_options() (
    local name="${1?}" cmdline="${2?}" expected="${3?}" out

    out="$(mktemp --tmpdir --directory "test-veritysetup-generator.XXXXXXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$out'" EXIT INT QUIT PIPE

    SYSTEMD_LOG_LEVEL=debug SYSTEMD_PROC_CMDLINE="veritytab=no $cmdline" "$generator" "$out" "$out" "$out"

    grep -F "attach '$name' '$DATA' '$HASH' '$USRHASH' '$expected'" "$out/systemd-veritysetup@$name.service"
)

check_options() {
    check_unit_options usr "$@"
}

# Without options, systemd-veritysetup reads the signature from the udev database.
check_options "usrhash=$USRHASH" "root-hash-signature=auto"

# systemd-veritysetup treats the option string "-" or "none" as no options, so the generator drops it.
check_options "usrhash=$USRHASH systemd.verity_usr_options=-" "root-hash-signature=auto"
check_options "usrhash=$USRHASH systemd.verity_usr_options=none" "root-hash-signature=auto"

# Options from the kernel command line follow the default, so that they override it.
check_options "usrhash=$USRHASH systemd.verity_usr_options=panic-on-corruption" \
              "root-hash-signature=auto,panic-on-corruption"
check_options "usrhash=$USRHASH systemd.verity_usr_options=root-hash-signature=/run/usr.sig" \
              "root-hash-signature=auto,root-hash-signature=/run/usr.sig"

# A signature that makes up the whole option string becomes a root-hash-signature= option. The generator
# escapes commas and backslashes in the signature, because systemd-veritysetup splits the options at commas.
# ExecStart= processes C escapes, so every backslash in the unit file is escaped once more.
check_options "usrhash=$USRHASH systemd.verity_usr_options=/run/usr.sig" \
              "root-hash-signature=auto,root-hash-signature=/run/usr.sig"
check_options "usrhash=$USRHASH systemd.verity_usr_options=base64:MIIB" \
              "root-hash-signature=auto,root-hash-signature=base64:MIIB"
check_options "usrhash=$USRHASH systemd.verity_usr_options=/run/a,b\\c.sig" \
              "root-hash-signature=auto,root-hash-signature=/run/a\\\\,b\\\\\\\\c.sig"

# roothash= gets the same options for systemd-veritysetup@root.service.
check_unit_options root "roothash=$USRHASH" "root-hash-signature=auto"
check_unit_options root "roothash=$USRHASH systemd.verity_root_options=panic-on-corruption" \
                   "root-hash-signature=auto,panic-on-corruption"
