#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail
shopt -s extglob

# General systemd-sysext tests

fake_roots_dir=/fake-roots

at_exit() {
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

trap at_exit EXIT

die() {
    echo "${*}"
    exit 1
}

prep_root() {
    local r=${1}; shift
    local h=${1}; shift

    if [[ -d ${r} ]]; then
        die "${r@Q} is being reused as a root, possibly a result of copy-pasting some test case and forgetting to rename the root directory name"
    fi

    mkdir -p "${r}${h}" "${r}/usr/lib" "${r}/var/lib/extensions" "${r}/var/lib/extensions.mutable"
}

prep_env() {
    local mode=${1}; shift

    export SYSTEMD_SYSEXT_MUTABLE_MODE=${mode}
}

drop_env() {
    unset -v SYSTEMD_SYSEXT_MUTABLE_MODE
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

hierarchy_ext_mut_path() {
    local r=${1}; shift
    local h=${1}; shift

    # /a/b/c -> a.b.c
    local n=${h}
    n="${n##+(/)}"
    n="${n%%+(/)}"
    n="${n//\//.}"

    printf '%s' "${r}/var/lib/extensions.mutable/${n}"
}

prep_ext_mut() {
    local p=${1}; shift

    mkdir -p "${p}"
    touch "${p}/preexisting-file-in-extensions-mutable"
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
        u:preexisting-file-in-extensions-mutable
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

# General systemd-sysext tests

#
# no extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# mutability disabled by default
#
# read-only merged
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
# no extension data in /var/lib/extensions.mutable/…, mutable hierarchy,
# mutability disabled by default
#
# read-only merged
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
# no extension data in /var/lib/extensions.mutable/…, no hierarchy either,
# mutability disabled by default
#
# read-only merged
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
# no extension data in /var/lib/extensions.mutable/…, an empty hierarchy,
# mutability disabled by default
#
# read-only merged
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
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy, mutability disabled-by-default
#
# read-only merged
#


fake_root=${fake_roots_dir}/simple-mutable-with-read-only-hierarchy-disabled
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-be-read-only" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy, auto-mutability
#
# mutable merged
#


fake_root=${fake_roots_dir}/simple-mutable-with-read-only-hierarchy
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

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
# extension data in /var/lib/extensions.mutable/…, missing hierarchy,
# auto-mutability
#
# mutable merged
#


fake_root=${fake_roots_dir}/simple-mutable-with-missing-hierarchy
hierarchy=/opt

prep_root "${fake_root}" "${hierarchy}"
rmdir "${fake_root}/${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}"
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# extension data in /var/lib/extensions.mutable/…, empty hierarchy, auto-mutability
#
# mutable merged
#


fake_root=${fake_roots_dir}/simple-mutable-with-empty-hierarchy
hierarchy=/opt

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

make_ro "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}"
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# /var/lib/extensions.mutable/… is a symlink to /some/other/dir, read-only
# hierarchy, auto-mutability
#
# mutable merged
#


fake_root=${fake_roots_dir}/mutable-symlink-with-read-only-hierarchy
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# generate extension writable data
ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}/upperdir"
prep_ext_mut "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

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
# /var/lib/extensions.mutable/… is a symlink to the hierarchy itself, auto-mutability
#
# for this to work, hierarchy must be mutable
#
# mutable merged
#


fake_root=${fake_roots_dir}/mutable-self-upper
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# generate extension writable data
ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}${hierarchy}"
prep_ext_mut "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

# prepare writable hierarchy
touch "${fake_root}${hierarchy}/preexisting-file-in-hierarchy"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h u
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test -f "${real_ext_dir}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"


#
# /var/lib/extensions.mutable/… is a symlink to the hierarchy itself, which is
# read-only, auto-mutability
#
# expecting a failure here
#


fake_root=${fake_roots_dir}/failure-self-upper-ro
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

# generate extension writable data
ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}${hierarchy}"
prep_ext_mut "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge && die "expected merge to fail"


#
# /var/lib/extensions.mutable/… is a dangling symlink, auto-mutability
#
# read-only merged
#


fake_root=${fake_roots_dir}/read-only-mutable-dangling-symlink
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
ln -sfTr "/should/not/exist/" "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=auto merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extensions.mutable/… exists, but it's ignored, mutability disabled explicitly
#
# read-only merged
#


fake_root=${fake_roots_dir}/disabled
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=no merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extensions.mutable/… exists, but it's imported instead
#
# read-only merged
#


fake_root=${fake_roots_dir}/imported
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=import merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h


#
# /var/lib/extensions.mutable/… does not exist, but mutability is enabled
# explicitly
#
# mutable merged
#


fake_root=${fake_roots_dir}/enabled
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

test ! -d "${ext_data_path}" || die "extensions.mutable should not exist"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=yes merge

test -d "${ext_data_path}" || die "extensions.mutable should exist now"
touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# /var/lib/extensions.mutable/… does not exist, auto-mutability
#
# read-only merged
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
# /var/lib/extensions.mutable/… does not exist, but mutability is enabled
# through an env var
#
# mutable merged
#


fake_root=${fake_roots_dir}/enabled-env-var
hierarchy=/usr

prep_env "yes"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

test ! -d "${ext_data_path}" || die "extensions.mutable should not exist"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

test -d "${ext_data_path}" || die "extensions.mutable should exist now"
touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable is not stored in expected location"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable disappeared from writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"
drop_env


#
# /var/lib/extensions.mutable/… does not exist, auto-mutability through an env
# var
#
# read-only merged
#


fake_root=${fake_roots_dir}/read-only-auto-env-var
hierarchy=/usr

prep_env "auto"
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
drop_env


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# auto-mutability through an env var
#
# mutable merged
#


fake_root=${fake_roots_dir}/auto-mutable-env-var
hierarchy=/usr

prep_env "auto"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

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
drop_env


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# mutability disabled through an env var
#
# read-only merged
#


fake_root=${fake_roots_dir}/env-var-disabled
hierarchy=/usr

prep_env "no"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-be-read-only" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
drop_env


#
# /var/lib/extensions.mutable/… exists, but it's imported instead through an
# env var
#
# read-only merged
#


fake_root=${fake_roots_dir}/imported-env-var
hierarchy=/usr

prep_env "import"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/should-still-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
drop_env


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# mutability enabled through an env var, but overridden with a command-line
# option
#
# read-only merged
#


fake_root=${fake_roots_dir}/env-var-overridden
hierarchy=/usr

prep_env "yes"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=no merge

touch "${fake_root}${hierarchy}/should-be-read-only" && die "${fake_root}${hierarchy} is not read-only"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
drop_env


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# ephemeral mutability, so extension data contents are ignored
#
# mutable merged
#


fake_root=${fake_roots_dir}/ephemeral
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=ephemeral merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not be stored in extension data"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not appear in writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# ephemeral mutability through an env var, so extension data contents are
# ignored
#
# mutable merged
#


fake_root=${fake_roots_dir}/ephemeral-env-var
hierarchy=/usr

prep_env "ephemeral"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not be stored in extension data"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not appear in writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"
drop_env


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# ephemeral import mutability, so extension data contents are imported too
#
# mutable merged
#


fake_root=${fake_roots_dir}/ephemeral-import
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=ephemeral-import merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not be stored in extension data"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not appear in writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"


#
# extension data in /var/lib/extensions.mutable/…, read-only hierarchy,
# ephemeral mutability through an env var, so extension data contents are
# imported too
#
# mutable merged
#


fake_root=${fake_roots_dir}/ephemeral-import-env-var
hierarchy=/usr

prep_env "ephemeral-import"
prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
prep_ext_mut "${ext_data_path}"

prep_ro_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-fail-on-read-only-fs" && die "${fake_root}${hierarchy} is not read-only"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" merge

touch "${fake_root}${hierarchy}/now-is-mutable" || die "${fake_root}${hierarchy} is not mutable"
check_usual_suspects_after_merge "${fake_root}" "${hierarchy}" e h u
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not be stored in extension data"

SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" unmerge

check_usual_suspects_after_unmerge "${fake_root}" "${hierarchy}" h
test ! -f "${ext_data_path}/now-is-mutable" || die "now-is-mutable should not appear in writable storage after unmerge"
test ! -f "${fake_root}${hierarchy}/now-is-mutable" || die "now-is-mutable did not disappear from hierarchy after unmerge"
drop_env


#
# extension data pointing to mutable hierarchy, ephemeral import mutability
#
# expecting a failure here
#


fake_root=${fake_roots_dir}/ephemeral-import-self
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}${hierarchy}"
prep_ext_mut "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

prep_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-succeed-on-read-only-fs" || die "${fake_root}${hierarchy} is not mutable"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=ephemeral-import merge && die 'expected merge to fail'


#
# extension data pointing to mutable hierarchy, import mutability
#
# expecting a failure here
#


fake_root=${fake_roots_dir}/import-self
hierarchy=/usr

prep_root "${fake_root}" "${hierarchy}"
gen_os_release "${fake_root}"
gen_test_ext_image "${fake_root}" "${hierarchy}"

ext_data_path=$(hierarchy_ext_mut_path "${fake_root}" "${hierarchy}")
real_ext_dir="${fake_root}${hierarchy}"
prep_ext_mut "${real_ext_dir}"
ln -sfTr "${real_ext_dir}" "${ext_data_path}"

prep_hierarchy "${fake_root}" "${hierarchy}"

touch "${fake_root}${hierarchy}/should-succeed-on-read-only-fs" || die "${fake_root}${hierarchy} is not mutable"

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="${hierarchy}" systemd-sysext --root="${fake_root}" --mutable=import merge && die 'expected merge to fail'

exit 0
