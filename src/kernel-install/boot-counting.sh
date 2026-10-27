# SPDX-License-Identifier: LGPL-2.1-or-later

is_valid_boot_count() {
    case "$1" in
        ''|*[!0-9-]*|[-]*|*-|*-*-*)
            return 1
            ;;
    esac
    return 0
}

remove_boot_counted_files() {
    boot_counted_prefix=$1
    boot_counted_suffix=$2
    boot_counted_message=$3
    shift 3

    for boot_counted_file in "$boot_counted_prefix"+*"$boot_counted_suffix"; do
        [ -e "$boot_counted_file" ] || [ -L "$boot_counted_file" ] || continue

        boot_counted_tries=${boot_counted_file#"$boot_counted_prefix"+}
        boot_counted_tries=${boot_counted_tries%"$boot_counted_suffix"}
        is_valid_boot_count "$boot_counted_tries" || continue

        [ "$KERNEL_INSTALL_VERBOSE" -gt 0 ] && \
            echo "$boot_counted_message '$boot_counted_file'."
        set -- "$@" "$boot_counted_file"
    done

    [ "$#" -eq 0 ] || rm -rf -- "$@"
}
