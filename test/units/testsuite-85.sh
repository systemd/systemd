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

    mkdir -p "${r}${h}" "${r}/usr/lib" "${r}/var/lib/extensions" "${r}/var/lib/extension-data"
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

hierarchy_ext_data_path() {
    local r=${1}; shift
    local h=${1}; shift

    # /a/b/c -> a.b.c
    local n=${h}
    n="${n##+(/)}"
    n="${n%%+(/)}"
    n="${n//\//.}"

    printf '%s' "${r}/var/lib/extension-data/${n}.local"
}

prep_ext_data() {
    local p=${1}; shift

    mkdir -p "${p}"
    touch "${p}/preexisting-file-in-extension-data"
}

make_ro() {
    local r=${1}; shift
    local h=${1}; shift

    mount -o bind "${r}${h}" "${r}${h}"
    mount -o bind,remount,ro "${r}${h}"
}

prep_ro_hierarchy() {
    local r=${1}; shift
    local h=${1}; shift

    touch "${r}${h}/preexisting-file-in-hierarchy"
    make_ro "${r}" "${h}"
}

# extra args:
# "e" for checking for the preexisting file in extension
# "h" for checking for the preexisting file in hierarchy
# "u" for checking for the preexisting file in upperdir
check_usual_suspects() {
    local root=${1}; shift
    local hierarchy=${1}; shift
    local message=${1}; shift

    local arg
    # shellcheck disable=SC2034 # the variables below are used indirectly
    local e='' h='' u=''

    for arg; do
        case ${arg} in
            e|h|u)
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
        u:preexisting-file-in-extension-data
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
# simple case, no extension data in /var/lib/extension-data/…
#


fake_root=${fake_roots_dir}/simple-read-only
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


#
# simple case, no extension data in /var/lib/extension-data/… and no hierarchy either
#


fake_root=${fake_roots_dir}/simple-read-only-missing-hierarchy
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
# simple case, no extension data in /var/lib/extension-data/… and an empty hierarchy
#


fake_root=${fake_roots_dir}/simple-read-only-empty-hierarchy
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
# simple case, extension data in /var/lib/extension-data/…
#


fake_root=${fake_roots_dir}/simple-mutable
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
prep_ext_data "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# simple case, extension data in /var/lib/extension-data/…, missing hierarchy
#


fake_root=${fake_roots_dir}/simple-mutable-missing-hierarchy
hierarchy=/opt

prep_root "${fake_root}" "${hierarchy}"
rmdir "${fake_root}/${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
prep_ext_data "${ext_data_path}"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}"
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# simple case, extension data in /var/lib/extension-data/…, empty hierarchy
#


fake_root=${fake_roots_dir}/simple-mutable-missing-hierarchy
hierarchy=/opt

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
prep_ext_data "${ext_data_path}"

make_ro "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}"
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# /var/lib/extension-data/… is a symlink to /some/other/dir
#


fake_root=${fake_roots_dir}/symlink
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# generate extension writable data
ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}/upperdir"
prep_ext_data "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# /var/lib/extension-data/… is a symlink to the hierarchy itself
#
# for this to work, hierarchy must be writable
#


fake_root=${fake_roots_dir}/self-upper
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# generate extension writable data
ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}${hierarchy}"
prep_ext_data "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

# prepare writable hierarchy
touch "${fake_root}${hierarchy}/preexisting-file-in-hierarchy"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"


#
# /var/lib/extension-data/… is a symlink to the hierarchy itself, which is read-only
#
# expecting a failure here
#


fake_root=${fake_roots_dir}/self-upper-ro
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# generate extension writable data
ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}${hierarchy}"
prep_ext_data "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge || die "expected merge to fail"


#
# /var/lib/extension-data/… is a dangling symlink, assuming immutable mode
#


fake_root=${fake_roots_dir}/dangling
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
ln -sfTr "/should/not/exist/" "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extension-data/… exists, but it's ignored
#


fake_root=${fake_roots_dir}/disabled
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
prep_ext_data "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=no merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extension-data/… exists, but it's imported instead
#


fake_root=${fake_roots_dir}/imported
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
prep_ext_data "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=import merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extension-data/… does not exist, but mutability is enabled anyway
#


fake_root=${fake_roots_dir}/enabled
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

test ! -d "${ext_data_path}" || die "extension-data should not exist"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=yes merge

test -d "${ext_data_path}" || die "extension-data should exist now"
touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# /var/lib/extension-data/… does not exist, mutability is set to auto (same as
# simple read-only, but explicit)
#


fake_root=${fake_roots_dir}/simple-read-only-explicit
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extension-data/… exists, mutability is set to auto (same as simple
# mutable, but explicit)
#


fake_root=${fake_roots_dir}/simple-mutable-explicit
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_data_path "${fake_root}" "${hierarchy}")
prep_ext_data "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# done
#


touch /testok
