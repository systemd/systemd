#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
# shellcheck disable=SC2233,SC2235
set -eux
set -o pipefail

shopt -s extglob

export SYSTEMD_LOG_LEVEL=debug

fake_roots_dir=/fake-roots

# shellcheck disable=SC2317
cleanup() {
    set +ex

    local tries=10 e
    local -a lines fake_roots_mounts

    while [[ ${tries} -gt 0 ]]; do
        tries=$((tries - 1))
        mapfile -t lines < <(mount | awk '{ print $3 }')
        fake_roots_mounts=()
        for e in "${lines[@]}"; do
            if [[ ${e} = "${fake_roots_dir}"/* ]]; then
                fake_roots_mounts+=( "${e}" )
            fi
        done
        if [[ ${#fake_roots_mounts[@]} -eq 0 ]]; then
            break
        fi
        for e in "${fake_roots_mounts[@]}"; do
            umount "${e}"
        done
    done
    rm -rf "${fake_roots_dir}"
}

trap cleanup EXIT

die() {
    echo "${*}"
    exit 1
}

prep_root() {
    local r=${1}; shift
    local h=${1}; shift

    mkdir -p "${r}${h}" "${r}/usr/lib" "${r}/var/lib/extensions"
}

gen_os_release() {
    local r=${1}; shift

    {
        echo "ID=testtest"
        echo "VERSION=1.2.3"
    } >"${r}/usr/lib/os-release"
}

gen_test_ext_image() {
    local r=${1}; shift
    local h=${1}; shift

    local n d f

    n='test-extension'
    d="${r}/var/lib/extensions/${n}"
    f="${d}/usr/lib/extension-release.d/extension-release.${n}"
    mkdir -p "$(dirname "${f}")"
    echo "ID=_any" >"${f}"
    mkdir -p "${d}/${h}"
    touch "${d}${h}/preexisting-file-in-extension-image"
}

make_ro() {
    local r=${1}; shift
    local h=${1}; shift

    mount -o bind "${r}${h}" "${r}${h}"
    mount -o bind,remount,ro "${r}${h}"
}

prep_hierarchy() {
    local r=${1}; shift
    local h=${1}; shift

    touch "${r}${h}/preexisting-file-in-hierarchy"
}

prep_ro_hierarchy() {
    local r=${1}; shift
    local h=${1}; shift

    prep_hierarchy "${r}" "${h}"
    make_ro "${r}" "${h}"
}

# extra args:
# "e" for checking for the preexisting file in extension
# "h" for checking for the preexisting file in hierarchy
check_usual_suspects() {
    local root=${1}; shift
    local hierarchy=${1}; shift
    local message=${1}; shift

    local arg
    # shellcheck disable=SC2034 # the variables below are used indirectly
    local e='' h=''

    for arg; do
        case ${arg} in
            e|h)
                local -n v=${arg}
                v=x
                unset -n v
                ;;
            *)
                die "invalid arg to ${0}: ${arg@Q}"
                ;;
        esac
    done

    # var name, file name
    local pairs=(
        e:preexisting-file-in-extension-image
        h:preexisting-file-in-hierarchy
    )
    local pair name file desc full_path
    for pair in "${pairs[@]}"; do
        name=${pair%%:*}
        file=${pair#*:}
        desc=${file//-/ }
        full_path="${root}${hierarchy}/${file}"
        local -n v=${name}
        if [[ -n ${v} ]]; then
            test -f "${full_path}" || {
                ls -la "$(dirname "${full_path}")"
                die "${desc} is missing ${message}"
            }
        else
            test ! -f "${full_path}" || {
                ls -la "$(dirname "${full_path}")"
                die "${desc} unexpectedly exists ${message}"
            }
        fi
        unset -n v
    done
}

check_usual_suspects_after_merge() {
    local r=${1}; shift
    local h=${1}; shift

    check_usual_suspects "${r}" "${h}" "after merge" "${@}"
}

check_usual_suspects_after_unmerge() {
    local r=${1}; shift
    local h=${1}; shift

    check_usual_suspects "${r}" "${h}" "after unmerge" "${@}"
}



#
# simple case, read-only hierarchy
#


fake_root=${fake_roots_dir}/simple-read-only-with-read-only-hierarchy
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only after unmerge"

#
# simple case, mutable hierarchy
#


fake_root=${fake_roots_dir}/simple-read-only-with-mutable-hierarchy
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

prep_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-succeed-on-mutable-fs" || die "${fake_root}${hierarchy} is not mutable"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h

touch "${fake_root}${hierarchy}/should-succeed-on-mutable-fs-again" || die "${fake_root}${hierarchy} is not mutable after unmerge"


#
# simple case, no hierarchy either
#


fake_root=${fake_roots_dir}/simple-read-only-with-missing-hierarchy
hierarchy=/opt

prep_root "${fake_root}" "${hierarchy}"
rmdir "${fake_root}/${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}"


#
# simple case, an empty hierarchy
#


fake_root=${fake_roots_dir}/simple-read-only-with-empty-hierarchy
hierarchy=/opt

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

make_ro "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}"


#
# done
#


touch /testok
