#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Utility functions for shell tests

# shellcheck disable=SC2034
[[ -e /var/tmp/.systemd_reboot_count ]] && REBOOT_COUNT="$(</var/tmp/.systemd_reboot_count)" || REBOOT_COUNT=0

assert_true() {(
    set +ex

    local rc

    "$@"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "FAIL: command '$*' failed with exit code $rc" >&2
        exit 1
    fi
)}

assert_eq() {(
    set +ex

    if [[ "${1?}" != "${2?}" ]]; then
        echo "FAIL: expected: '$2' actual: '$1'" >&2
        exit 1
    fi
)}

assert_le() {(
    set +ex

    if [[ "${1:?}" -gt "${2:?}" ]]; then
        echo "FAIL: '$1' > '$2'" >&2
        exit 1
    fi
)}


assert_in() {(
    set +ex

    if ! [[ "${2?}" =~ ${1?} ]]; then
        echo "FAIL: '$1' not found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_not_in() {(
    set +ex

    if [[ "${2?}" =~ ${1?} ]]; then
        echo "FAIL: '$1' found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_rc() {(
    set +ex

    local rc exp="${1?}"

    shift
    "$@"
    rc=$?
    assert_eq "$rc" "$exp"
)}

assert_not_reached() {
    echo >&2 "Code should not be reached at ${BASH_SOURCE[1]}:${BASH_LINENO[1]}, function ${FUNCNAME[1]}()"
    exit 1
}

run_and_grep() {(
    set +ex

    local expression
    local log ec
    local exp_ec=0

    # Invert the grep condition - i.e. check if the expression is _not_ in command's output
    if [[ "${1:?}" == "-n" ]]; then
        exp_ec=1
        shift
    fi

    expression="${1:?}"
    shift

    if [[ $# -eq 0 ]]; then
        echo >&2 "FAIL: Not enough arguments for ${FUNCNAME[0]}()"
        return 1
    fi

    log="$(mktemp)"
    if ! "$@" |& tee "${log:?}"; then
        echo >&2 "FAIL: Command '$*' failed"
        return 1
    fi

    grep -qE "$expression" "$log" && ec=0 || ec=$?
    if [[ "$exp_ec" -eq 0 && "$ec" -ne 0 ]]; then
        echo >&2 "FAIL: Expression '$expression' not found in the output of '$*'"
        return 1
    elif [[ "$exp_ec" -ne 0 && "$ec" -eq 0 ]]; then
        echo >&2 "FAIL: Expression '$expression' found in the output of '$*'"
        return 1
    fi

    rm -f "$log"
)}

get_cgroup_hierarchy() {
    case "$(stat -c '%T' -f /sys/fs/cgroup)" in
        cgroup2fs)
            echo "unified"
            ;;
        tmpfs)
            if [[ -d /sys/fs/cgroup/unified && "$(stat -c '%T' -f /sys/fs/cgroup/unified)" == cgroup2fs ]]; then
                echo "hybrid"
            else
                echo "legacy"
            fi
            ;;
        *)
            echo >&2 "Failed to determine host's cgroup hierarchy"
            exit 1
    esac
}

runas() {
    local userid="${1:?}"
    shift
    XDG_RUNTIME_DIR=/run/user/"$(id -u "$userid")" setpriv --reuid="$userid" --init-groups "$@"
}

coverage_create_nspawn_dropin() {
    # If we're collecting coverage, bind mount the $BUILD_DIR into the nspawn
    # container so gcov can update the counters. This is mostly for standalone
    # containers, as machinectl stuff is handled by overriding the systemd-nspawn@.service
    # (see test/test-functions:install_systemd())
    local root="${1:?}"
    local container

    if [[ -z "${COVERAGE_BUILD_DIR:-}" ]]; then
        return 0
    fi

    container="$(basename "$root")"
    mkdir -p "/run/systemd/nspawn"
    echo -ne "[Files]\nBind=$COVERAGE_BUILD_DIR\n" >"/run/systemd/nspawn/${container:?}.nspawn"
}

create_dummy_container() {
    local root="${1:?}"

    if [[ ! -d /testsuite-13-container-template ]]; then
        echo >&2 "Missing container template, probably not running in TEST-13-NSPAWN?"
        exit 1
    fi

    mkdir -p "$root"
    cp -a /testsuite-13-container-template/* "$root"
    coverage_create_nspawn_dropin "$root"
}

# Bump the reboot counter and call systemctl with the given arguments
systemctl_final() {
    local counter

    if [[ $# -eq 0 ]]; then
        echo >&2 "Missing arguments"
        exit 1
    fi

    [[ -e /var/tmp/.systemd_reboot_count ]] && counter="$(</var/tmp/.systemd_reboot_count)" || counter=0
    echo "$((counter + 1))" >/var/tmp/.systemd_reboot_count

    systemctl "$@"
}

cgroupfs_supports_user_xattrs() {
    local xattr

    xattr="user.supported_$RANDOM"
    # shellcheck disable=SC2064
    trap "setfattr --remove=$xattr /sys/fs/cgroup || :" RETURN

    setfattr --name="$xattr" --value=254 /sys/fs/cgroup
    [[ "$(getfattr --name="$xattr" --absolute-names --only-values /sys/fs/cgroup)" -eq 254 ]]
}

tpm_has_pcr() {
    local algorithm="${1:?}"
    local pcr="${2:?}"

    [[ -f "/sys/class/tpm/tpm0/pcr-$algorithm/$pcr" ]]
}

openssl_supports_kdf() {
    local kdf="${1:?}"

    # The arguments will need to be adjusted to make this work for other KDFs than SSKDF,
    # but let's do that when/if the need arises
    openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt key:foo -out /dev/null "$kdf"
}

kernel_supports_lsm() {
    local lsm="${1:?}"
    local items item

    if [[ ! -e /sys/kernel/security/lsm ]]; then
        echo "/sys/kernel/security/lsm doesn't exist, assuming $lsm is not supported"
        return 1
    fi

    mapfile -t -d, items </sys/kernel/security/lsm
    for item in "${items[@]}"; do
        if [[ "$item" == "$lsm" ]]; then
            return 0
        fi
    done

    return 1
}

MOUNTED_USR_OVERLAY=false

maybe_mount_usr_overlay() {
    if [[ ! -w /usr ]]; then
        mkdir -p /tmp/usr-overlay/{upperdir,workdir}
        mount -t overlay -o lowerdir=/usr,upperdir=/tmp/usr-overlay/upperdir,workdir=/tmp/usr-overlay/workdir overlay /usr
	MOUNTED_USR_OVERLAY=true
    fi
}

maybe_umount_usr_overlay() {
    if "$MOUNTED_USR_OVERLAY"; then
        umount -l /usr
    fi
}
