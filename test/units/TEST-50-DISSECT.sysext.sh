#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

FAKE_ROOTS_DIR="$(mktemp -d --tmpdir="" fake-roots-XXX)"
FSTYPE=$(stat --file-system --format "%T" /usr)

shopt -s nullglob

# shellcheck disable=SC2317
at_exit() {
    set +ex

    local target

    # Note: `cat` here is used intentionally, so we iterate over our own copy of /proc/mounts. Otherwise
    #       things get very confusing once we start unmounting things, due to changing file offsets.
    # shellcheck disable=SC2002
    cat /proc/mounts | while read -r _ target _ _ _ _; do
        if [[ "$target" =~ ^"$FAKE_ROOTS_DIR" ]]; then
            umount -Rv "$target"
        fi
    done

    rm -rf "${FAKE_ROOTS_DIR}"
}

trap at_exit EXIT

# Clears the trap command - it needs to be invoked for every test-case subshell
# so prepending commands with prepend_trap inside the subshell won't preserve
# the trap commands from outer shell.
init_trap() {
    trap - EXIT
}

prepend_trap() {
    set +x

    local command=${1}; shift
    local previous_commands

    previous_commands=$(trap -p EXIT)
    if [[ -z $previous_commands ]]; then
        previous_commands=':'
    else
        previous_commands=${previous_commands#'trap -- '}
        previous_commands=${previous_commands%' EXIT'}
        previous_commands=$(xargs <<<"$previous_commands")
    fi

    # shellcheck disable=SC2064 # We use double quotes on purpose here.
    trap "${command}; ${previous_commands}" EXIT

    set -x
}

prepare_root() {
    local root=${1:-}
    local hierarchy=${2:?}
    local dir

    if [[ -n $root ]] && [[ -d $root ]]; then
        echo >&2 "Directory $root already exists, possible copy-paste error?"
        exit 1
    fi

    local -a leftovers=( "$root/var/lib/extensions/"* "$root/var/lib/extensions.mutable/"* )
    if [[ ${#leftovers[@]} -gt 0 ]]; then
        echo >&2 "Leftovers remained, make sure to clean them up in the test case: ${leftovers[*]}"
        exit 1
    fi

    for dir in "$hierarchy" "/usr/lib" "/var/lib/extensions/" "/var/lib/extensions.mutable"; do
        mkdir -p "$root$dir"
    done

    if [[ -e $root/usr/lib/os-release ]]; then
        mv "$root/usr/lib/os-release" "$root/usr/lib/os-release.orig"
    fi

    {
        echo "ID=testtest"
        echo "VERSION=1.2.3"
    } >"$root/usr/lib/os-release"

    prepend_trap "cleanup_os_release ${root@Q}"
}

cleanup_os_release() {
    # shellcheck disable=SC2317 # It is not unreachable, used in a trap couple lines above.
    local root=${1:-}

    # shellcheck disable=SC2317 # It is not unreachable, used in a trap couple lines above.
    rm -f "$root/usr/lib/os-release"
    # shellcheck disable=SC2317 # It is not unreachable, used in a trap couple lines above.
    if [[ -e $root/usr/lib/os-release.orig ]]; then
        # shellcheck disable=SC2317 # It is not unreachable, used in a trap couple lines above.
        mv "$root/usr/lib/os-release.orig" "$root/usr/lib/os-release"
    fi
}

prepare_extension_image() {
    local root=${1:-}
    local hierarchy=${2:?}
    local ext_dir ext_release name

    name="test-extension"
    ext_dir="$root/var/lib/extensions/$name"
    ext_release="$ext_dir/usr/lib/extension-release.d/extension-release.$name"
    mkdir -p "${ext_release%/*}"
    echo "ID=_any" >"$ext_release"
    mkdir -p "$ext_dir/$hierarchy"
    touch "$ext_dir$hierarchy/preexisting-file-in-extension-image"

    prepend_trap "rm -rf ${ext_dir@Q}"
}

prepare_extension_mutable_dir() {
    local dir=${1:?}

    mkdir -p "$dir"
    touch "$dir/preexisting-file-in-extensions-mutable"
    prepend_trap "rm -rf ${dir@Q}"
}

make_read_only() {
    local root=${1:-}
    local hierarchy=${2:?}

    mount -o bind,ro "$root$hierarchy" "$root$hierarchy"
    prepend_trap "umount ${root@Q}${hierarchy@Q}"
}

prepare_hierarchy() {
    local root=${1:-}
    local hierarchy=${2:?}
    local file

    file="$root$hierarchy/preexisting-file-in-hierarchy"
    touch "$file"
    prepend_trap "rm -f ${file@Q}"
}

prepare_read_only_hierarchy() {
    local root=${1:-}
    local hierarchy=${2:?}

    prepare_hierarchy "$root" "$hierarchy"
    make_read_only "$root" "$hierarchy"
}

move_existing_hierarchy_aside() {
    local root=${1:-}
    local hierarchy=${2:?}

    if [[ -z $root ]] && [[ $hierarchy = /usr ]]; then
        echo >&2 "Hell no, not moving /usr aside"
        exit 1
    fi

    local path=$root$hierarchy

    if [[ -e $path ]]; then
        mv "$path" "$path.orig"
        prepend_trap "mv ${path@Q}.orig ${path@Q}"
    fi
}

# Extra arguments:
#   -e: check for a preexisting file in extension
#   -h: check for a preexisting file in hierarchy
#   -u: check for a preexisting file in upperdir
extension_verify() {
    local root=${1:-}
    local hierarchy=${2:?}
    local message=${3:?}
    shift 3
    # Map each option to a pre-defined file name
    local -A option_files_map=(
        [e]="preexisting-file-in-extension-image"
        [h]="preexisting-file-in-hierarchy"
        [u]="preexisting-file-in-extensions-mutable"
    )
    local -A args=(
        [e]=0
        [h]=0
        [u]=0
    )
    local file full_path opt option

    while getopts "ehu" opt; do
        case "$opt" in
            e|h|u)
                args["$opt"]=1
                ;;
            *)
                echo >&2 "Unxexpected option: $opt"
                exit 1
        esac
    done

    for option in "${!option_files_map[@]}"; do
        file=${option_files_map["$option"]}
        full_path="$root$hierarchy/$file"

        if [[ ${args["$option"]} -ne 0 ]]; then
            if [[ ! -f $full_path ]]; then
                ls -la "$root$hierarchy"
                echo >&2 "Expected file '$file' to exist under $root$hierarchy $message"
                exit 1
            fi
        else
            if [[ -f $full_path ]]; then
                ls -la "$root$hierarchy"
                echo >&2 "Expected file '$file' to not exist under $root$hierarchy $message"
                exit 1
            fi
        fi
    done
}

extension_verify_after_merge() (
    set +x

    local root=${1:-}
    local hierarchy=${2:?}
    shift 2

    extension_verify "$root" "$hierarchy" "after merge" "$@"
)

extension_verify_after_unmerge() (
    set +x

    local root=${1:-}
    local hierarchy=${2:?}
    shift 2

    extension_verify "$root" "$hierarchy" "after unmerge" "$@"
)

run_systemd_sysext() {
    local root=${1:-}
    shift

    local -a sysext_args
    sysext_args=()

    if [[ -n $root ]]; then
        sysext_args+=( "--root=$root" )
    fi
    sysext_args+=( "$@" )
    systemd-sysext "${sysext_args[@]}"
}

# General systemd-sysext tests

run_sysext_tests() {
    # The roots_dir variable may be empty - in such case all the tests will run
    # on /, otherwise they will run on $roots_dir/<SEPARATE_DIR_FOR_TEST>.
    local roots_dir=${1}; shift

    # Each test runs in a subshell, so we can use traps for cleanups without
    # clobbering toplevel traps, and we can do skips by invoking "exit 0".

( init_trap
: "No extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled by default, read-only merged"
fake_root=${roots_dir:+"$roots_dir/simple-read-only-with-read-only-hierarchy"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
)


( init_trap
: "No extension data in /var/lib/extensions.mutable/…, mutable hierarchy, mutability disabled by default, read-only merged"
fake_root=${roots_dir:+"$roots_dir/simple-read-only-with-mutable-hierarchy"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root$hierarchy/should-succeed-on-mutable-fs"

run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
touch "$fake_root$hierarchy/should-succeed-on-mutable-fs-again"
)


( init_trap
: "No extension data in /var/lib/extensions.mutable/…, no hierarchy either, mutability disabled by default, read-only merged"
fake_root=${roots_dir:+"$roots_dir/simple-read-only-with-missing-hierarchy"}
hierarchy=/opt

move_existing_hierarchy_aside "$fake_root" "$hierarchy"
prepare_root "$fake_root" "$hierarchy"
rmdir "$fake_root/$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"
)


( init_trap
: "No extension data in /var/lib/extensions.mutable/…, empty hierarchy, mutability disabled by default, read-only merged"
fake_root=${roots_dir:+"$roots_dir/simple-read-only-with-empty-hierarchy"}
hierarchy=/opt

move_existing_hierarchy_aside "$fake_root" "$hierarchy"
prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
make_read_only "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled by default, read-only merged"
fake_root=${roots_dir:+"$roots_dir/simple-mutable-with-read-only-hierarchy-disabled"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-be-read-only")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, auto-mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/simple-mutable-with-read-only-hierarchy"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, missing hierarchy, auto-mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/simple-mutable-with-missing-hierarchy"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

move_existing_hierarchy_aside "$fake_root" "$hierarchy"
prepare_root "$fake_root" "$hierarchy"
rmdir "$fake_root/$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"

run_systemd_sysext "$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -u
test -f "$extension_data_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, empty hierarchy, auto-mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/simple-mutable-with-empty-hierarchy"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

move_existing_hierarchy_aside "$fake_root" "$hierarchy"
prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
make_read_only "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -u
test -f "$extension_data_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "/var/lib/extensions.mutable/… is a symlink to other dir, R/O hierarchy, auto-mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/mutable-symlink-with-read-only-hierarchy"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root/upperdir"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepend_trap "rm -f ${extension_data_dir@Q}"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "/var/lib/extensions.mutable/… is a symlink to the hierarchy itself, mutable hierarchy, auto-mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/mutable-self-upper"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepend_trap "rm -f ${extension_data_dir@Q}"
touch "$fake_root$hierarchy/preexisting-file-in-hierarchy"

run_systemd_sysext "$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h -u
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"
)


( init_trap
: "/var/lib/extensions.mutable/… is a symlink to the hierarchy itself, R/O hierarchy, auto-mutability, expected fail"
fake_root=${roots_dir:+"$roots_dir/failure-self-upper-ro"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepend_trap "rm -f ${extension_data_dir@Q}"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

(! run_systemd_sysext "$fake_root" --mutable=auto merge)
)


( init_trap
: "/var/lib/extensions.mutable/… is a dangling symlink, auto-mutability, read-only merged"
fake_root=${roots_dir:+"$roots_dir/read-only-mutable-dangling-symlink"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
ln -sfTr "/should/not/exist/" "$extension_data_dir"
prepend_trap "rm -f ${extension_data_dir@Q}"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=auto merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "/var/lib/extensions.mutable/… exists but ignored, mutability disabled explicitly, read-only merged"
fake_root=${roots_dir:+"$roots_dir/disabled"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=no merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "/var/lib/extensions.mutable/… exists but is imported instead, read-only merged"
fake_root=${roots_dir:+"$roots_dir/imported"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=import merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "/var/lib/extensions.mutable/… does not exist, mutability enabled, mutable merged"
fake_root=${roots_dir:+"$roots_dir/enabled"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_data_dir_usr="$fake_root/var/lib/extensions.mutable/usr"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")
test ! -d "$extension_data_dir"

run_systemd_sysext "$fake_root" --mutable=yes merge
# systemd-sysext with --mutable=yes creates extensions.mutable directory for
# the hierarchy, so delete it after the test
prepend_trap "rm -rf ${extension_data_dir@Q}"
# systemd-sysext with --mutable=yes creates extensions.mutable directory also
# for the /usr hierarchy, because the image needs to have
# /usr/lib/extension-release.d/extension-release.<NAME> file - this causes the
# /usr hierarchy to also become mutable
prepend_trap "rm -rf ${extension_data_dir_usr@Q}"
test -d "$extension_data_dir"
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test -f "$extension_data_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "/var/lib/extensions.mutable/… does not exist, auto-mutability, read-only merged"
fake_root=${roots_dir:+"$roots_dir/simple-read-only-explicit"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=auto merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "/var/lib/extensions.mutable/… does not exist, mutability enabled through env var, mutable merged"
fake_root=${roots_dir:+"$roots_dir/enabled-env-var"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_data_dir_usr="$fake_root/var/lib/extensions.mutable/usr"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")
test ! -d "$extension_data_dir"

SYSTEMD_SYSEXT_MUTABLE_MODE=yes run_systemd_sysext "$fake_root" merge
# systemd-sysext with --mutable=yes creates extensions.mutable directory for
# the hierarchy, so delete it after the test
prepend_trap "rm -rf ${extension_data_dir@Q}"
# systemd-sysext with --mutable=yes creates extensions.mutable directory also
# for the /usr hierarchy, because the image needs to have
# /usr/lib/extension-release.d/extension-release.<NAME> file - this causes the
# /usr hierarchy to also become mutable
prepend_trap "rm -rf ${extension_data_dir_usr@Q}"
test -d "$extension_data_dir"
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_MUTABLE_MODE=yes run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "/var/lib/extensions.mutable/… does not exist, auto-mutability enabled through env var, read-only merged"
fake_root=${roots_dir:+"$roots_dir/read-only-auto-env-var"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=auto run_systemd_sysext "$fake_root" --mutable=auto merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_MUTABLE_MODE=auto run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, auto-mutability enabled through env var, mutable merged"
fake_root=${roots_dir:+"$roots_dir/auto-mutable-env-var"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=auto run_systemd_sysext "$fake_root" merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_MUTABLE_MODE=auto run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled through env var, read-only merged"
fake_root=${roots_dir:+"$roots_dir/env-var-disabled"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=no run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-be-read-only")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_MUTABLE_MODE=no run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "/var/lib/extensions.mutable/… exists but is imported through env var, read-only merged"
fake_root=${roots_dir:+"$roots_dir/imported-env-var"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=import run_systemd_sysext "$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u

SYSTEMD_SYSEXT_MUTABLE_MODE=import run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability enabled through env var but overridden via CLI option, read-only merged"
fake_root=${roots_dir:+"$roots_dir/env-var-overridden"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=yes run_systemd_sysext "$fake_root" --mutable=no merge
(! touch "$fake_root$hierarchy/should-be-read-only")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_MUTABLE_MODE=yes run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/ephemeral"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=ephemeral merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test ! -f "$extension_data_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral mutability through env var, mutable merged"
fake_root=${roots_dir:+"$roots_dir/ephemeral-env-var"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral run_systemd_sysext "$fake_root" merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test ! -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral import mutability, mutable merged"
fake_root=${roots_dir:+"$roots_dir/ephemeral-import"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

run_systemd_sysext "$fake_root" --mutable=ephemeral-import merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test ! -f "$extension_data_dir/now-is-mutable"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral import mutability through env var, mutable merged"
fake_root=${roots_dir:+"$roots_dir/ephemeral-import-env-var"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral-import run_systemd_sysext "$fake_root" merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test ! -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral-import run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"
)


( init_trap
: "Extension data pointing to mutable hierarchy, ephemeral import mutability, expected fail"
fake_root=${roots_dir:+"$roots_dir/ephemeral-import-self"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepend_trap "rm -f ${extension_data_dir@Q}"
prepare_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root$hierarchy/should-succeed-on-read-only-fs"

(! run_systemd_sysext "$fake_root" --mutable=ephemeral-import merge)
)


( init_trap
: "Extension data pointing to mutable hierarchy, import mutability, expected fail"
fake_root=${roots_dir:+"$roots_dir/import-self"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepend_trap "rm -f ${extension_data_dir@Q}"
prepare_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root$hierarchy/should-succeed-on-read-only-fs"

(! run_systemd_sysext "$fake_root" --mutable=import merge)
)


for mutable_mode in no yes ephemeral; do
    ( init_trap
    : "Check if merging the hierarchy does not change its permissions, checking with --mutable=${mutable_mode}"

    fake_root=${roots_dir:+"$roots_dir/perm-checks-mutable-$mutable_mode"}
    hierarchy=/opt
    extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

    [[ "$FSTYPE" == "fuseblk" ]] && exit 0

    prepare_root "$fake_root" "$hierarchy"
    prepare_extension_image "$fake_root" "$hierarchy"
    prepare_extension_mutable_dir "$extension_data_dir"
    prepare_read_only_hierarchy "${fake_root}" "${hierarchy}"

    full_path="$fake_root$hierarchy"
    permissions_before_merge=$(stat --format=%A "$full_path")

    run_systemd_sysext "$fake_root" "--mutable=$mutable_mode" merge
    if [[ $mutable_mode = yes ]]; then
        # systemd-sysext with --mutable=yes creates extensions.mutable
        # directory also for the /usr hierarchy, because the image needs to
        # have /usr/lib/extension-release.d/extension-release.<NAME> file -
        # this causes the /usr hierarchy to also become mutable
        extension_data_dir_usr="$fake_root/var/lib/extensions.mutable/usr"
        prepend_trap "rm -rf ${extension_data_dir_usr@Q}"
    fi

    permissions_after_merge=$(stat --format=%A "$full_path")

    run_systemd_sysext "$fake_root" unmerge

    permissions_after_unmerge=$(stat --format=%A "$full_path")

    if [[ "$permissions_before_merge" != "$permissions_after_merge" ]]; then
        echo >&2 "Broken hierarchy permissions after merging with mutable mode ${mutable_mode@Q}, expected ${permissions_before_merge@Q}, got ${permissions_after_merge@Q}"
        exit 1
    fi

    if [[ "$permissions_before_merge" != "$permissions_after_unmerge" ]]; then
        echo >&2 "Broken hierarchy permissions after unmerging with mutable mode ${mutable_mode@Q}, expected ${permissions_before_merge@Q}, got ${permissions_after_unmerge@Q}"
        exit 1
    fi
    )
done


( init_trap
: "Check if merging fails in case of invalid mutable directory permissions"

fake_root=${roots_dir:+"$roots_dir/mutable-directory-with-invalid-permissions"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_hierarchy "$fake_root" "$hierarchy"

old_mode=$(stat --format '%#a' "$fake_root$hierarchy")
chmod 0755 "$fake_root$hierarchy"
prepend_trap "chmod ${old_mode@Q} ${fake_root@Q}${hierarchy@Q}"
chmod 0700 "$extension_data_dir"

(! run_systemd_sysext "$fake_root" --mutable=yes merge)
)

} # End of run_sysext_tests


# For preparing /, we need mutable /usr/. If it is read only, skip running the
# sysext tests on /.
if [[ -w /usr ]]; then
    run_sysext_tests ''
fi
run_sysext_tests "$FAKE_ROOTS_DIR"

install_extension_images

# Test that mountpoints are carried over into and back from the sysext overlayfs.
ln -s /tmp/app0.raw /var/lib/extensions/app0.raw
mkdir /tmp/foo
mount --bind /tmp/foo /usr/share
systemd-sysext merge
test -f /usr/lib/systemd/system/some_file
mountpoint /usr/share
touch /tmp/foo/abc
test -f /usr/share/abc
umount /usr/share
test ! -f /usr/share/abc
mount --bind /tmp/foo /usr/share
systemd-sysext unmerge
test ! -f /usr/lib/systemd/system/some_file
mountpoint /usr/share
umount /usr/share

exit 0
