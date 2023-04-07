#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

link_endswith() {
    [[ -h "${1:?}" && "$(readlink "${1:?}")" =~ ${2:?}$ ]]
}

link_eq() {
    [[ -h "${1:?}" && "$(readlink "${1:?}")" == "${2:?}" ]]
}

# Get the value from a 'key=value' assignment
opt_get_arg() {
    local arg

    IFS="=" read -r _ arg <<< "${1:?}"
    test -n "$arg"
    echo "$arg"
}

in_initrd() {
    [[ "${SYSTEMD_IN_INITRD:-0}" -ne 0 ]]
}

# Check if we're parsing host's fstab in initrd
in_initrd_host() {
    in_initrd && [[ "${SYSTEMD_SYSROOT_FSTAB:-/dev/null}" != /dev/null ]]
}

in_container() {
    systemd-detect-virt -qc
}

# Filter out "unwanted" options, i.e. options that the fstab-generator doesn't
# propagate to the final mount unit
opt_filter_consumed() {(
    set +x
    local opt split_options filtered_options

    IFS="," read -ra split_options <<< "${1:?}"
    for opt in "${split_options[@]}"; do
        if [[ "$opt" =~ ^x-systemd.device-timeout= ]]; then
            continue
        fi

        filtered_options+=("$opt")
    done

    IFS=","; printf "%s" "${filtered_options[*]}"
)}

# Run the given generator $1 with target directory $2 - clean the target
# directory beforehand
run_and_list() {
    local generator="${1:?}"
    local out_dir="${2:?}"

    rm -fr "${out_dir:?}"/*
    SYSTEMD_LOG_LEVEL="${SYSTEMD_LOG_LEVEL:-debug}" "$generator" "$out_dir"
    ls -lR "$out_dir"
}
