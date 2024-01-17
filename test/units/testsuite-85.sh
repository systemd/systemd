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

prep_ro_hierarchy() {
    local r=${1}; shift
    local h=${1}; shift

    touch "${r}${h}/preexisting-file-in-hierarchy"
    mount -o bind "${r}${h}" "${r}${h}"
    mount -o bind,remount,ro "${r}${h}"
}

check_usual_suspects() {
    local r=${1}; shift
    local h=${1}; shift

    local ed
    ed=$(hierarchy_ext_data_path "${r}" "${h}")

    test -f "${ed}/now-is-mutable" || die "now-is-mutable is not stored in expected location"
    test -f "${r}${h}/preexisting-file-in-extension-data" || die "preexisting file from extension data is missing"
    test -f "${r}${h}/preexisting-file-in-extension-image" || die "preexisting file from extension image is missing"
    test -f "${r}${h}/preexisting-file-in-hierarchy" || die "preexisting file from base hierarchy is missing"
}

hierarchy=/usr


#
# simple case, extension data in /var/lib/extension-data/…
#


fake_root=${fake_roots_dir}/simple

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
check_usual_suspects "${fake_root}" "${hierarchy}"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"
test ! -f "${fake_root}${hierarchy}/preexisting-file-in-extension-data" || die "preexisting file from extension data did not disappear from hierarchy after unmerge"
test ! -f "${fake_root}${hierarchy}/preexisting-file-in-extension-image" || die "preexisting file from extension image did not disappear from hierarchy after unmerge"
test -f "${fake_root}${hierarchy}/preexisting-file-in-hierarchy" || die "preexisting file from base hierarchy data disappeared from hierarchy after unmerge"


#
# /var/lib/extension-data/… is a symlink to /some/other/dir
#


fake_root=${fake_roots_dir}/symlink

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
check_usual_suspects "${fake_root}" "${hierarchy}"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"
test ! -f "${fake_root}${hierarchy}/preexisting-file-in-extension-data" || die "preexisting file from extension data did not disappear from hierarchy after unmerge"
test ! -f "${fake_root}${hierarchy}/preexisting-file-in-extension-image" || die "preexisting file from extension image did not disappear from hierarchy after unmerge"
test -f "${fake_root}${hierarchy}/preexisting-file-in-hierarchy" || die "preexisting file from base hierarchy data disappeared from hierarchy after unmerge"


#
# /var/lib/extension-data/… is a symlink to the hierarchy itself
#
# for this to work, hierarchy must be writable
#


fake_root=${fake_roots_dir}/self-upper

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
check_usual_suspects "${fake_root}" "${hierarchy}"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

ls -la "${fake_root}/${hierarchy}"

test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test -f "${fake_root}${hierarchy}/preexisting-file-in-extension-data" || die "preexisting file from extension data disappeared from hierarchy after unmerge"
test ! -f "${fake_root}${hierarchy}/preexisting-file-in-extension-image" || die "preexisting file from extension image did not disappear from hierarchy after unmerge"
test -f "${fake_root}${hierarchy}/preexisting-file-in-hierarchy" || die "preexisting file from base hierarchy data disappeared from hierarchy after unmerge"


touch /testok
