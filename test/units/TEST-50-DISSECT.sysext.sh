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
        echo "ID_LIKE=\"foobar test_alike something-else\""
        echo "VERSION=1.2.3"
    } >"$root/usr/lib/os-release"

    if [[ -e $root/etc/os-release ]] && [[ ! -L $root/etc/os-release ]]; then
        mv "$root/etc/os-release" "$root/etc/os-release.orig"
        cp "$root/usr/lib/os-release" "$root/etc/os-release"
    fi

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
    # shellcheck disable=SC2317 # It is not unreachable, used in a trap couple lines above.
    if [[ -e $root/etc/os-release.orig ]]; then
        # shellcheck disable=SC2317 # It is not unreachable, used in a trap couple lines above.
        mv "$root/etc/os-release.orig" "$root/etc/os-release"
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

prepare_extension_image_with_matching_id() {
    local root=${1:-}
    local hierarchy=${2:?}
    local ext_dir ext_release name

    name="test-extension-matching-id"
    ext_dir="$root/var/lib/extensions/$name"
    ext_release="$ext_dir/usr/lib/extension-release.d/extension-release.$name"
    mkdir -p "${ext_release%/*}"
    echo "ID=testtest" >"$ext_release"
    mkdir -p "$ext_dir/$hierarchy"
    touch "$ext_dir$hierarchy/preexisting-file-in-extension-image"

    prepend_trap "rm -rf ${ext_dir@Q}"
}

prepare_extension_image_with_matching_id_like() {
    local root=${1:-}
    local hierarchy=${2:?}
    local ext_dir ext_release name

    name="test-extension-matching-id-like"
    ext_dir="$root/var/lib/extensions/$name"
    ext_release="$ext_dir/usr/lib/extension-release.d/extension-release.$name"
    mkdir -p "${ext_release%/*}"
    echo "ID=test_alike" >"$ext_release"
    mkdir -p "$ext_dir/$hierarchy"
    touch "$ext_dir$hierarchy/preexisting-file-in-extension-image"

    prepend_trap "rm -rf ${ext_dir@Q}"
}

prepare_extension_image_raw() {
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
    mksquashfs "$ext_dir" "$ext_dir.raw" -all-root -noappend -quiet
    rm -rf "$ext_dir"

    prepend_trap "rm -rf ${ext_dir@Q}.raw"
}

prepare_extension_image_raw_verity() {
    local root=${1:-}
    local hierarchy=${2:?}
    local ext_dir ext_release name tmpcrt

    name="test-extension"
    ext_dir="$root/var/lib/extensions/$name"
    ext_release="$ext_dir/usr/lib/extension-release.d/extension-release.$name"
    tmpcrt=$(mktemp --directory "/tmp/test-sysext.crt.XXXXXXXXXX")

    prepend_trap "rm -rf ${ext_dir@Q} ${ext_dir@Q}.raw '$root/etc/verity.d/test-ext.crt' '$tmpcrt'"

    mkdir -p "${ext_release%/*}"
    echo "ID=_any" >"$ext_release"
    mkdir -p "$ext_dir/$hierarchy"
    touch "$ext_dir$hierarchy/preexisting-file-in-extension-image"
    tee >"$tmpcrt/verity.openssl.cnf" <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
C = DE
ST = Test State
L = Test Locality
O = Org Name
OU = Org Unit Name
CN = Common Name
emailAddress = test@email.com
EOF
    openssl req \
        -config "$tmpcrt/verity.openssl.cnf" \
        -new -x509 \
        -newkey rsa:1024 \
        -keyout "$tmpcrt/test-ext.key" \
        -out "$tmpcrt/test-ext.crt" \
        -days 365 \
        -nodes
    systemd-repart --make-ddi=sysext \
        --private-key="$tmpcrt/test-ext.key" --certificate="$tmpcrt/test-ext.crt" \
        --copy-source="$ext_dir" "$ext_dir.raw"
    rm -rf "$ext_dir"
    mkdir -p "$root/etc/verity.d"
    mv "$tmpcrt/test-ext.crt" "$root/etc/verity.d/"
    rm -rf "$tmpcrt"
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

extension_verify_mount_option() (
    local target=${1:?}
    local option=${2:?}

    grep "^sysext" /proc/mounts | while read -r _ tgt _ opts _ _; do
        if [[ "$target" == "$tgt" && ! "$opts" =~ .*"$option".* ]]; then
            echo >&2 "Mount options ($opts) do not include expected option ($option)"
            exit 1
        fi
    done
)

extension_verify_status_json() (
    local root=${1:-}
    local hierarchy=${2:?}
    local expected_extensions=${3:?}
    local status_json since_filter

    # Whether a hierarchy is merged is told by "since", not by "extensions": an empty array is also
    # reported for a hierarchy merged in mutable mode without any extensions.
    if [[ "$expected_extensions" == "[]" ]]; then
        since_filter='.since == null'
    else
        since_filter='.since != null'
    fi

    status_json=$(run_systemd_sysext "$root" status --json=pretty)
    jq -e --arg h "$hierarchy" --argjson e "$expected_extensions" \
       "any(.[]; .hierarchy == \$h and .extensions == \$e and $since_filter)" >/dev/null <<<"$status_json"
)

# Checks that exactly one mount is established on a path, i.e. no stale copy hides below the visible one
verify_single_mount() {
    local path=${1:?}
    local message=${2:?}
    local n

    mountpoint "$path"
    n=$(awk -v t="$path" '$5 == t' /proc/self/mountinfo | wc -l)
    if [ "$n" != 1 ]; then
        echo >&2 "Expected exactly one mount on $path $message, found $n"
        exit 1
    fi
}

# Checks that exactly one overlayfs is mounted on a hierarchy
verify_single_overlay() {
    local path=${1:?}
    local message=${2:?}
    local n

    n=$(awk -v t="$path" '$5 == t && $0 ~ / - overlay /' /proc/self/mountinfo | wc -l)
    if [ "$n" != 1 ]; then
        echo >&2 "Expected exactly one overlayfs on $path $message, found $n"
        exit 1
    fi
}

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
extension_verify_status_json "$fake_root" "$hierarchy" '["test-extension"]'

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
extension_verify_status_json "$fake_root" "$hierarchy" '[]'
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
)


( init_trap
: "No extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled by default, read-only merged, default, mount options"
fake_root=${roots_dir:+"$roots_dir/simple-read-only-with-read-only-hierarchy-options"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS="metacopy=off,noatime"\
 run_systemd_sysext "$fake_root" merge

extension_verify_mount_option "$hierarchy" metacopy=off \
|| (! extension_verify_mount_option "$hierarchy" metacopy=on)
extension_verify_mount_option "$hierarchy" noatime

run_systemd_sysext "$fake_root" unmerge
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
: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, auto-mutability, mutable merged, mount options"
fake_root=${roots_dir:+"$roots_dir/simple-mutable-with-read-only-hierarchy-options"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" --mutable=auto merge

extension_verify_mount_option "$fake_root$hierarchy" index=off \
|| (! extension_verify_mount_option "$fake_root$hierarchy" index=on)
extension_verify_mount_option "$fake_root$hierarchy" metacopy=off \
|| (! extension_verify_mount_option "$fake_root$hierarchy" metacopy=on)
extension_verify_mount_option "$fake_root$hierarchy" noatime
(! extension_verify_mount_option "$fake_root$hierarchy" redirect_dir=off)

SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS="relatime,metacopy=on"\
 run_systemd_sysext "$fake_root" --mutable=auto refresh

(! extension_verify_mount_option "$fake_root$hierarchy" metacopy=off) \
|| extension_verify_mount_option "$fake_root$hierarchy" metacopy=on
(! extension_verify_mount_option "$fake_root$hierarchy" noatime)
extension_verify_mount_option "$fake_root$hierarchy" relatime

run_systemd_sysext "$fake_root" unmerge
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
: "Malformed work_dir metadata is rejected without removing unrelated paths"
[[ -z "$roots_dir" ]] && exit 0

fake_root="$roots_dir/empty-work-dir"
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
work_dir_file="$fake_root$hierarchy/.systemd-sysext/work_dir"
traversal_target="$roots_dir/work-dir-traversal-target"
absolute_target="$fake_root/work-dir-absolute-target"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root/root-sentinel"
mkdir "$traversal_target" "$absolute_target"
touch "$traversal_target/sentinel" "$absolute_target/sentinel"
prepend_trap "rm -rf ${traversal_target@Q} ${absolute_target@Q}"

run_systemd_sysext "$fake_root" --mutable=yes merge
prepend_trap "rm -rf ${extension_data_dir@Q}"

# Mutable overlays bind-mount the metadata directory read-only. Unmount that bind first to simulate
# corrupted on-disk metadata, then try malformed work_dir values.
umount "$fake_root$hierarchy/.systemd-sysext"
work_dir=$(<"$work_dir_file")

for invalid_work_dir in "" ../work-dir-traversal-target /work-dir-absolute-target; do
    printf '%s\n' "$invalid_work_dir" >"$work_dir_file"
    (! run_systemd_sysext "$fake_root" unmerge)
    test -f "$fake_root/root-sentinel"
    test -f "$traversal_target/sentinel"
    test -f "$absolute_target/sentinel"
done

# Restore valid metadata and unmerge normally, so the test case leaves no mounted hierarchy behind.
printf '%s\n' "$work_dir" >"$work_dir_file"
run_systemd_sysext "$fake_root" unmerge
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
: "Check if merging an extension with matching ID succeeds"
fake_root=${roots_dir:+"$roots_dir/matching-id"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_with_matching_id "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "Check if merging an extension that matches host ID_LIKE succeeds"
fake_root=${roots_dir:+"$roots_dir/matching-id-like"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_with_matching_id_like "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)


( init_trap
: "Check if merging fails in case of invalid mutable directory permissions"

fake_root=${roots_dir:+"$roots_dir/mutable-directory-with-invalid-permissions"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_data_dir_usr="$fake_root/var/lib/extensions.mutable/usr"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepend_trap "rm -rf ${extension_data_dir@Q}"
prepend_trap "rm -rf ${extension_data_dir_usr@Q}"
prepare_hierarchy "$fake_root" "$hierarchy"

old_mode=$(stat --format '%#a' "$fake_root$hierarchy")
chmod 0755 "$fake_root$hierarchy"
prepend_trap "chmod ${old_mode@Q} ${fake_root@Q}${hierarchy@Q}"
chmod 0700 "$extension_data_dir"

(! run_systemd_sysext "$fake_root" --mutable=yes merge)
)

( init_trap
: "Check if merging fails in case of --root= being an initrd but the extension is not for it"
# Since this is really about whether --root= gets prepended for the /etc/initrd-release check,
# this also tests the more interesting reverse case that we are in the initrd and prepare
# the mounts for the final system with --root=/sysroot
fake_root=${roots_dir:+"$roots_dir/initrd-env-with-non-initrd-extension"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mkdir -p "${fake_root}/etc"
touch "${fake_root}/etc/initrd-release"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

# Should be a no-op, thus we also don't run unmerge afterwards (otherwise the test is broken)
run_systemd_sysext "$fake_root" merge
if ! extension_verify_status_json "$fake_root" "$hierarchy" '[]'; then
    echo >&2 "Extension got loaded for an initrd structure passed as --root= while the extension does not declare itself compatible with the initrd scope"
    exit 1
fi
rm "${fake_root}/etc/initrd-release"
)

( init_trap
: "Check config file support for --root="
fake_root=${roots_dir:+"$roots_dir/config-file"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0
if [ "$roots_dir" = "" ]; then
    echo >&2 "Skipping test when --root= is not used"
    exit 0
fi

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

mkdir -p "$fake_root/etc/systemd/"
{ echo "[SysExt]" ; echo "Mutable=auto" ; } > "$fake_root/etc/systemd/sysext.conf"
# Config file should be picked up with --root= set
run_systemd_sysext "$fake_root" merge
MNTOPT=$(findmnt "$fake_root$hierarchy" --first-only --direction backward --raw --noheadings -o VFS-OPTIONS | grep -o rw || true)
if [ "$MNTOPT" != "rw" ]; then
    echo >&2 "Merge did not pick up mutable setting from config file"
    exit 1
fi
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
run_systemd_sysext "$fake_root" unmerge

# CLI arg should be able to overwrite config file
run_systemd_sysext "$fake_root" merge --mutable=no
MNTOPT=$(findmnt "$fake_root$hierarchy" --first-only --direction backward --raw --noheadings -o VFS-OPTIONS | grep -o ro || true)
if [ "$MNTOPT" != "ro" ]; then
    echo >&2 "Merge did not pick up CLI arg to overwrite mutable setting from config file"
    exit 1
fi
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
run_systemd_sysext "$fake_root" unmerge

{ echo "[SysExt]" ; echo "ImagePolicy=root=signed+absent:usr=signed+absent" ; } > "$fake_root/etc/systemd/sysext.conf"
# Config file should be picked up with --root= set
if run_systemd_sysext "$fake_root" merge; then
    echo >&2 "Merge did not fail with strict image policy in config file"
    exit 1
fi
# CLI arg should be able to overwrite config file
run_systemd_sysext "$fake_root" merge --image-policy="*"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
run_systemd_sysext "$fake_root" unmerge
)

( init_trap
: "Check if verity user certs get loaded from --root="
fake_root=${roots_dir:+"$roots_dir/verity-user-cert-from-root"}
hierarchy=/opt

# On OpenSUSE Tumbleweed EROFS is not supported
if [ -e /usr/lib/modprobe.d/60-blacklist_fs-erofs.conf ]; then
    echo >&2 "Skipping test due to missing erofs support"
    exit 0
fi

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw_verity "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge --image-policy=root=signed+absent:usr=signed+absent
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)

# A couple of symlink tests follow below

( init_trap
: "Check if following a relative extension directory symlink works with and without --root="
fake_root=${roots_dir:+"$roots_dir/follow-relative-dir-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/othername-extension"
ln -s "../../othername-extension" "$fake_root/var/lib/extensions/test-extension"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/othername-extension"
)

( init_trap
: "Check if following an absolute extension directory symlink works with and without --root="
fake_root=${roots_dir:+"$roots_dir/follow-absolute-dir-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/othername-extension"
ln -s "/var/othername-extension" "$fake_root/var/lib/extensions/test-extension"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/othername-extension"
)

( init_trap
: "Check if following a relative extension image symlink works with and without --root="
fake_root=${roots_dir:+"$roots_dir/follow-relative-image-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/othername-extension.raw"
ln -s "../../othername-extension.raw" "$fake_root/var/lib/extensions/test-extension.raw"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/othername-extension.raw"
)

( init_trap
: "Check if following an absolute extension image symlink works with and without --root="
fake_root=${roots_dir:+"$roots_dir/follow-absolute-image-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/othername-extension.raw"
ln -s "/var/othername-extension.raw" "$fake_root/var/lib/extensions/test-extension.raw"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/othername-extension.raw"
)

# And now a couple of vpick tests, including following symlinks

( init_trap
: "Check if vpick works for directory extensions"
fake_root=${roots_dir:+"$roots_dir/vpick-dir"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mkdir -p "$fake_root/var/lib/extensions/test-extension.v"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/lib/extensions/test-extension.v/test-extension_1.0"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.v"
)

( init_trap
: "Check if vpick works for image extensions"
fake_root=${roots_dir:+"$roots_dir/vpick-image"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mkdir -p "$fake_root/var/lib/extensions/test-extension.raw.v"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/lib/extensions/test-extension.raw.v/test-extension_1.0.raw"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.raw.v"
)

( init_trap
: "Check if vpick works for directory extensions if .v is a relative symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-dir-relative-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mkdir -p "$fake_root/var/test-extension-vpick"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/test-extension-vpick/test-extension_1.0"
ln -s "../../test-extension-vpick" "$fake_root/var/lib/extensions/test-extension.v"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.v" "$fake_root/var/test-extension-vpick"
)

( init_trap
: "Check if vpick works for directory extensions if .v is an absolute symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-dir-absolute-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mkdir -p "$fake_root/var/test-extension-vpick"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/test-extension-vpick/test-extension_1.0"
ln -s "/var/test-extension-vpick" "$fake_root/var/lib/extensions/test-extension.v"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.v" "$fake_root/var/test-extension-vpick"
)

( init_trap
: "Check if vpick works for image extensions if .v is a relative symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-image-relative-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mkdir -p "$fake_root/var/test-extension-vpick"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/test-extension-vpick/test-extension_1.0.raw"
ln -s "../../test-extension-vpick" "$fake_root/var/lib/extensions/test-extension.raw.v"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.raw.v" "$fake_root/var/test-extension-vpick"
)

( init_trap
: "Check if vpick works for image extensions if .v is an absolute symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-image-absolute-symlink"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mkdir -p "$fake_root/var/test-extension-vpick"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/test-extension-vpick/test-extension_1.0.raw"
ln -s "/var/test-extension-vpick" "$fake_root/var/lib/extensions/test-extension.raw.v"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.raw.v" "$fake_root/var/test-extension-vpick"
)

( init_trap
: "Check if vpick works for directory extensions if inside a .v there is a relative symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-dir-relative-symlink-inside"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/othername-extension"
mkdir -p "$fake_root/var/lib/extensions/test-extension.v"
ln -s "../../../othername-extension" "$fake_root/var/lib/extensions/test-extension.v/test-extension_1.0"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.v" "$fake_root/var/othername-extension"
)

( init_trap
: "Check if vpick works for directory extensions if inside a .v there is an absolute symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-dir-absolute-symlink-inside"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
mv -T "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/othername-extension"
mkdir -p "$fake_root/var/lib/extensions/test-extension.v"
ln -s "/var/othername-extension" "$fake_root/var/lib/extensions/test-extension.v/test-extension_1.0"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.v" "$fake_root/var/othername-extension"
)

( init_trap
: "Check if vpick works for image extensions if inside a .v there is a relative symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-image-relative-symlink-inside"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/othername-extension.raw"
mkdir -p "$fake_root/var/lib/extensions/test-extension.raw.v"
ln -s "../../../othername-extension.raw" "$fake_root/var/lib/extensions/test-extension.raw.v/test-extension_1.0.raw"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.raw.v" "$fake_root/var/othername-extension.raw"
)

( init_trap
: "Check if vpick works for image extensions if inside a .v there is an absolute symlink"
fake_root=${roots_dir:+"$roots_dir/vpick-image-absolute-symlink-inside"}
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw "$fake_root" "$hierarchy"
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/othername-extension.raw"
mkdir -p "$fake_root/var/lib/extensions/test-extension.raw.v"
ln -s "/var/othername-extension.raw" "$fake_root/var/lib/extensions/test-extension.raw.v/test-extension_1.0.raw"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
rm -rf "$fake_root/var/lib/extensions/test-extension.raw.v" "$fake_root/var/othername-extension.raw"
)

# Done with the above vpick symlink tests for --root= and without

( init_trap
: "Check if refresh skips correctly"
fake_root=${roots_dir:+"$roots_dir/refresh-skip"}
hierarchy=/opt

findmnt --kernel=listmount >/dev/null || {
    echo >&2 "Can't run test on old kernel, skipping test."
    exit 0
}

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
# The mountinfo ID gets reused and is useless here, we require a unique ID from listmount
MOUNTID1=$(findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy")
run_systemd_sysext "$fake_root" refresh
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
MOUNTID2=$(findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy")
if [ "$MOUNTID1" != "$MOUNTID2" ]; then
    echo >&2 "Unexpected remount with 'refresh'"
    exit 1
fi
rm -rf "$fake_root/var/lib/extensions/test-extension2"
cp -ar "$fake_root/var/lib/extensions/test-extension" "$fake_root/var/lib/extensions/test-extension2"
rm -rf "$fake_root/var/lib/extensions/test-extension"
mv "$fake_root/var/lib/extensions/test-extension2" "$fake_root/var/lib/extensions/test-extension"
run_systemd_sysext "$fake_root" refresh
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
MOUNTID3=$(findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy")
if [ "$MOUNTID2" = "$MOUNTID3" ]; then
    echo >&2 "Unexpected skip with 'refresh'"
    exit 1
fi

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)

( init_trap
: "Check that refresh does a skip if verity image changes file handle but has same hash"
fake_root=${roots_dir:+"$roots_dir/refresh-skip-verity-filehandle-same-hash"}
hierarchy=/opt

# On OpenSUSE Tumbleweed EROFS is not supported
if [ -e /usr/lib/modprobe.d/60-blacklist_fs-erofs.conf ]; then
    echo >&2 "Skipping test due to missing erofs support"
    exit 0
fi

findmnt --kernel=listmount >/dev/null || {
    echo >&2 "Can't run test on old kernel, skipping test."
    exit 0
}

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image_raw_verity "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
# The mountinfo ID gets reused and is useless here, we require a unique ID from listmount
MOUNTID1=$(findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy")
run_systemd_sysext "$fake_root" refresh
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
MOUNTID2=$(findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy")
if [ "$MOUNTID1" != "$MOUNTID2" ]; then
    echo >&2 "Unexpected remount with 'refresh'"
    exit 1
fi
# Force a new file handle (get a new inode)
mv "$fake_root/var/lib/extensions/test-extension.raw" "$fake_root/var/lib/extensions/test-extension2.raw"
cp "$fake_root/var/lib/extensions/test-extension2.raw" "$fake_root/var/lib/extensions/test-extension.raw"
rm "$fake_root/var/lib/extensions/test-extension2.raw"
run_systemd_sysext "$fake_root" refresh
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
MOUNTID3=$(findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy")
if [ "$MOUNTID2" != "$MOUNTID3" ]; then
    echo >&2 "Unexpected remount with 'refresh' after verity image file handle changed"
    exit 1
fi

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
)

( init_trap
: "Check EXTENSION_RESTART_UNITS= (re)starts units after merge and stops vanished ones on unmerge"
# Talks to the real service manager, skip the --root= variant (it is a no-op there)
if [ "$roots_dir" != "" ]; then
    exit 0
fi

ext_name="test-restart-extension"
ext_dir="/var/lib/extensions/$ext_name"
host_unit="test-restart-host.service"
host_unit_file="/run/systemd/system/$host_unit"
ext_unit="test-restart-ext.service"

cat >"$host_unit_file" <<EOF
[Service]
Type=simple
ExecStart=sleep 9999
EOF
prepend_trap "rm -f ${host_unit_file@Q}; systemctl stop ${host_unit@Q} 2>/dev/null || :"
systemctl daemon-reload
systemctl start "$host_unit"
host_pid_before=$(systemctl show -P MainPID "$host_unit")

mkdir -p "$ext_dir/usr/lib/extension-release.d" "$ext_dir/usr/lib/systemd/system"
prepend_trap "rm -rf ${ext_dir@Q}"
cat >"$ext_dir/usr/lib/extension-release.d/extension-release.$ext_name" <<EOF
ID=_any
ARCHITECTURE=_any
EXTENSION_RELOAD_MANAGER=1
EXTENSION_RESTART_UNITS="$host_unit $ext_unit"
EOF
cat >"$ext_dir/usr/lib/systemd/system/$ext_unit" <<EOF
[Service]
Type=simple
ExecStart=sleep 9999
EOF

# --no-reload skips both the daemon-reload and the restarts
systemd-sysext merge --no-reload
systemd-sysext refresh --always-refresh=yes --no-reload
if [ "$(systemctl show -P MainPID "$host_unit")" != "$host_pid_before" ]; then
    echo >&2 "Unexpected restart of host unit"
    exit 1
fi
if systemctl --quiet is-active "$ext_unit"; then
    echo >&2 "Unexpected start of extension unit"
    exit 1
fi
systemd-sysext unmerge --no-reload

# merge: host unit is restarted (new PID), extension unit is started
systemd-sysext merge
host_pid_merged=$(systemctl show -P MainPID "$host_unit")
if [ "$host_pid_before" = "$host_pid_merged" ]; then
    echo >&2 "Missing restart of host unit"
    exit 1
fi
if ! systemctl --quiet is-active "$ext_unit"; then
    echo >&2 "Missing start of extension unit"
    exit 1
fi
host_pid_before_refresh="$host_pid_merged"
systemd-sysext refresh --always-refresh=yes
host_pid_merged=$(systemctl show -P MainPID "$host_unit")
if [ "$host_pid_before_refresh" = "$host_pid_merged" ]; then
    echo >&2 "Missing restart of host unit after refresh"
    exit 1
fi
if ! systemctl --quiet is-active "$ext_unit"; then
    echo >&2 "Missing start of extension unit"
    exit 1
fi

# unmerge: host unit file is still in /run -> restart again (new PID)
# but extension unit file is gone -> fallback to StopUnit
systemd-sysext unmerge
host_pid_unmerged=$(systemctl show -P MainPID "$host_unit")
if [ "$host_pid_merged" = "$host_pid_unmerged" ]; then
    echo >&2 "Missing restart of host unit"
    exit 1
fi
if systemctl --quiet is-active "$ext_unit"; then
    echo >&2 "Missing stop of extension unit"
    exit 1
fi
)

( init_trap
: "Check EXTENSION_RELOAD_OR_RESTART_UNITS= reloads units after merge and stops vanished ones on unmerge"
# Talks to the real service manager, skip the --root= variant (it is a no-op there)
if [ "$roots_dir" != "" ]; then
    exit 0
fi

ext_name="test-reload-or-restart-extension"
ext_dir="/var/lib/extensions/$ext_name"
host_unit="test-reload-or-restart-host.service"
host_unit_file="/run/systemd/system/$host_unit"
ext_unit="test-reload-or-restart-ext.service"
host_stamp="/run/test-reload-or-restart-host.stamp"
ext_stamp="/run/test-reload-or-restart-ext.stamp"

cat >"$host_unit_file" <<EOF
[Service]
Type=simple
ExecStart=sleep 9999
ExecReload=touch $host_stamp
EOF
prepend_trap "rm -f ${host_unit_file@Q} ${host_stamp@Q}; systemctl stop ${host_unit@Q} 2>/dev/null || :"
systemctl daemon-reload
systemctl start "$host_unit"
host_pid_before=$(systemctl show -P MainPID "$host_unit")

mkdir -p "$ext_dir/usr/lib/extension-release.d" "$ext_dir/usr/lib/systemd/system"
prepend_trap "rm -rf ${ext_dir@Q} ${ext_stamp@Q}"
cat >"$ext_dir/usr/lib/extension-release.d/extension-release.$ext_name" <<EOF
ID=_any
ARCHITECTURE=_any
EXTENSION_RELOAD_OR_RESTART_UNITS="$host_unit $ext_unit"
EOF
cat >"$ext_dir/usr/lib/systemd/system/$ext_unit" <<EOF
[Service]
Type=simple
ExecStart=sleep 9999
ExecReload=touch $ext_stamp
EOF

# merge: host unit supports reload -> reloaded (same PID, stamp file created),
# extension unit is started (no reload because it was not running yet)
rm -f "$host_stamp" "$ext_stamp"
systemd-sysext merge
host_pid_merged=$(systemctl show -P MainPID "$host_unit")
if [ "$host_pid_before" != "$host_pid_merged" ]; then
    echo >&2 "Unexpected restart of host unit (should have reloaded)"
    exit 1
fi
if [ ! -e "$host_stamp" ]; then
    echo >&2 "Host unit was not reloaded on merge (stamp missing)"
    exit 1
fi
if ! systemctl --quiet is-active "$ext_unit"; then
    echo >&2 "Missing start of extension unit"
    exit 1
fi
ext_pid_merged=$(systemctl show -P MainPID "$ext_unit")

# refresh: both units already running and reload-capable -> reloaded, MainPIDs unchanged,
# both stamp files re-created
rm -f "$host_stamp" "$ext_stamp"
systemd-sysext refresh --always-refresh=yes
host_pid_refreshed=$(systemctl show -P MainPID "$host_unit")
if [ "$host_pid_merged" != "$host_pid_refreshed" ]; then
    echo >&2 "Unexpected restart of host unit on refresh (should have reloaded)"
    exit 1
fi
if [ ! -e "$host_stamp" ]; then
    echo >&2 "Host unit was not reloaded on refresh (stamp missing)"
    exit 1
fi
ext_pid_refreshed=$(systemctl show -P MainPID "$ext_unit")
if [ "$ext_pid_merged" != "$ext_pid_refreshed" ]; then
    echo >&2 "Unexpected restart of extension unit on refresh (should have reloaded)"
    exit 1
fi
if [ ! -e "$ext_stamp" ]; then
    echo >&2 "Extension unit was not reloaded on refresh (stamp missing)"
    exit 1
fi

# unmerge: host unit file still in /run -> reloaded again (same PID, stamp re-created)
# but extension unit file is gone -> fallback to StopUnit
rm -f "$host_stamp" "$ext_stamp"
systemd-sysext unmerge
host_pid_unmerged=$(systemctl show -P MainPID "$host_unit")
if [ "$host_pid_refreshed" != "$host_pid_unmerged" ]; then
    echo >&2 "Unexpected restart of host unit on unmerge (should have reloaded)"
    exit 1
fi
if [ ! -e "$host_stamp" ]; then
    echo >&2 "Host unit was not reloaded on unmerge (stamp missing)"
    exit 1
fi
if systemctl --quiet is-active "$ext_unit"; then
    echo >&2 "Missing stop of extension unit"
    exit 1
fi
)

( init_trap
: "Nested tmpfs submounts under the hierarchy survive merge/refresh/unmerge round-trip"
fake_root=${roots_dir:+"$roots_dir/nested-submounts"}
hierarchy=/opt

# Don't run the test if the inner mount won't be preserved due to an old kernel
if ! systemd-analyze compare-versions "$(uname -r)" ge 5.12; then
    echo >&2 "Kernel too old for mount_setattr (need >= 5.12), skipping nested submount test"
    exit 0
fi

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"

# Two tmpfs mounts, one nested in the hierarchy under the other. Reproduces the nested mount layout from
# https://github.com/flatcar/Flatcar/issues/2111 and verifies that we preserve nested mounts across merge,
# refresh, and unmerge.
outer_mp="$fake_root$hierarchy/outer"
inner_mp="$outer_mp/inner"
mkdir -p "$outer_mp"
mount -t tmpfs tmpfs "$outer_mp"
prepend_trap "umount -l ${outer_mp@Q} 2>/dev/null || true"
mkdir -p "$inner_mp"
mount -t tmpfs tmpfs "$inner_mp"
prepend_trap "umount -l ${inner_mp@Q} 2>/dev/null || true"
touch "$outer_mp/outer-marker"
touch "$inner_mp/inner-marker"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
mountpoint "$outer_mp"
mountpoint "$inner_mp"
test -f "$outer_mp/outer-marker"
test -f "$inner_mp/inner-marker"

run_systemd_sysext "$fake_root" refresh --always-refresh=yes
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
mountpoint "$outer_mp"
mountpoint "$inner_mp"
test -f "$outer_mp/outer-marker"
test -f "$inner_mp/inner-marker"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
mountpoint "$outer_mp"
mountpoint "$inner_mp"
test -f "$outer_mp/outer-marker"
test -f "$inner_mp/inner-marker"
)

# Run once with mounting beneath (the default) and once forcing the fallback path taken on kernels without
# support for it, where the old overlayfs is unmounted before the new one is mounted
for mount_beneath in yes no; do
( init_trap
: "Failed refresh leaves the existing merge and its submounts untouched, successful refresh replaces it (mount beneath: $mount_beneath)"
# shellcheck disable=SC2031 # The setting is meant to be confined to this test case's subshell
export SYSTEMD_SYSEXT_MOUNT_BENEATH=$mount_beneath
fake_root=${roots_dir:+"$roots_dir/refresh-failure-$mount_beneath"}
hierarchy=/opt

# Identifies the overlayfs instance on the hierarchy by its unique mount ID from listmount. Without that
# (kernels before 6.8) use the device number instead: each instance has its own anonymous one, and since a
# new instance is set up while the previous one is still mounted, consecutive ones never share it.
if findmnt --kernel=listmount >/dev/null; then
    overlay_id() {
        findmnt --kernel=listmount -o UNIQ-ID --raw --noheadings --target "$fake_root$hierarchy"
    }
else
    overlay_id() {
        stat -c %d "$fake_root$hierarchy"
    }
fi
if ! systemd-analyze compare-versions "$(uname -r)" ge 5.12; then
    echo >&2 "Kernel too old for mount_setattr (need >= 5.12), skipping test"
    exit 0
fi

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"

# A submount that exists before the first merge
submount="$fake_root$hierarchy/submount"
mkdir -p "$submount"
prepend_trap "rmdir ${submount@Q} 2>/dev/null || true"
mount -t tmpfs tmpfs "$submount"
prepend_trap "umount -l ${submount@Q} 2>/dev/null || true"
touch "$submount/marker"

# Mount point for a submount that is added on top of the merged (read-only) hierarchy later
later_submount="$fake_root$hierarchy/later"
mkdir -p "$later_submount"
prepend_trap "rmdir ${later_submount@Q} 2>/dev/null || true"

# Nested inside the later submount, added between two refreshes
nested_submount="$later_submount/nested"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
OVERLAYID1=$(overlay_id)
# The submount is carried over into the merged hierarchy, the original below it is detached
verify_single_mount "$submount" "after merge"
test -f "$submount/marker"

# Add a submount on top of the merged hierarchy
mount -t tmpfs tmpfs "$later_submount"
prepend_trap "umount -l ${later_submount@Q} 2>/dev/null || true"
touch "$later_submount/later-marker"

# An unknown overlayfs mount option makes assembling the new overlayfs fail. The existing merge must survive
# this, including the submounts.
if SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS=nonexistent_option=1 run_systemd_sysext "$fake_root" refresh --always-refresh=yes; then
    echo >&2 "Refresh with an invalid overlayfs mount option unexpectedly succeeded"
    exit 1
fi
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
OVERLAYID2=$(overlay_id)
if [ "$OVERLAYID1" != "$OVERLAYID2" ]; then
    echo >&2 "Failed refresh replaced the existing merge"
    exit 1
fi
verify_single_overlay "$fake_root$hierarchy" "after failed refresh"
# The injected failure happens while building /usr/, which is the first hierarchy, so check that one too
test -f "$fake_root/usr/.systemd-sysext/extensions"
verify_single_overlay "$fake_root/usr" "after failed refresh"
verify_single_mount "$submount" "after failed refresh"
test -f "$submount/marker"
verify_single_mount "$later_submount" "after failed refresh"
test -f "$later_submount/later-marker"

# A successful refresh replaces the merge, keeps both submounts, and leaves exactly one overlayfs behind
run_systemd_sysext "$fake_root" refresh --always-refresh=yes
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
OVERLAYID3=$(overlay_id)
if [ "$OVERLAYID2" = "$OVERLAYID3" ]; then
    echo >&2 "Refresh did not replace the existing merge"
    exit 1
fi
verify_single_overlay "$fake_root$hierarchy" "after refresh"
verify_single_overlay "$fake_root/usr" "after refresh"
verify_single_mount "$submount" "after refresh"
test -f "$submount/marker"
verify_single_mount "$later_submount" "after refresh"
test -f "$later_submount/later-marker"

# Add a nested submount between two refreshes
mkdir -p "$nested_submount"
mount -t tmpfs tmpfs "$nested_submount"
prepend_trap "umount -l ${nested_submount@Q} 2>/dev/null || true"
touch "$nested_submount/nested-marker"

run_systemd_sysext "$fake_root" refresh --always-refresh=yes
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
OVERLAYID4=$(overlay_id)
if [ "$OVERLAYID3" = "$OVERLAYID4" ]; then
    echo >&2 "Second refresh did not replace the existing merge"
    exit 1
fi
verify_single_overlay "$fake_root$hierarchy" "after second refresh"
verify_single_overlay "$fake_root/usr" "after second refresh"
verify_single_mount "$submount" "after second refresh"
test -f "$submount/marker"
verify_single_mount "$later_submount" "after second refresh"
test -f "$later_submount/later-marker"
verify_single_mount "$nested_submount" "after second refresh"
test -f "$nested_submount/nested-marker"

# All of them survive the unmerge, too
run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
verify_single_mount "$submount" "after unmerge"
test -f "$submount/marker"
verify_single_mount "$later_submount" "after unmerge"
test -f "$later_submount/later-marker"
verify_single_mount "$nested_submount" "after unmerge"
test -f "$nested_submount/nested-marker"
)
done

( init_trap
: "Refresh unmerges a hierarchy that is no longer provided by any extension"
fake_root=${roots_dir:+"$roots_dir/refresh-dropped-hierarchy"}
hierarchy=/opt

if ! systemd-analyze compare-versions "$(uname -r)" ge 5.12; then
    echo >&2 "Kernel too old for mount_setattr (need >= 5.12), skipping test"
    exit 0
fi

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"

submount="$fake_root$hierarchy/submount"
mkdir -p "$submount"
mount -t tmpfs tmpfs "$submount"
prepend_trap "umount -l ${submount@Q} 2>/dev/null || true"
touch "$submount/marker"

run_systemd_sysext "$fake_root" merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
# The extension-release file makes /usr/ part of the merge, too
test -f "$fake_root/usr/.systemd-sysext/extensions"
mountpoint "$submount"
test -f "$submount/marker"

# Drop the hierarchy from the extension by emptying its directory, the refresh then unmerges it while /usr/
# stays merged. An empty hierarchy directory in the extension counts as not provided. This relies on the
# extension-release file living below /usr/, hence make sure that's not the hierarchy we empty.
if [ "$hierarchy" = "/usr" ]; then
    echo >&2 "This test requires a hierarchy other than /usr"
    exit 1
fi
find "$fake_root/var/lib/extensions/test-extension$hierarchy" -mindepth 1 -delete
run_systemd_sysext "$fake_root" refresh --always-refresh=yes
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -e "$fake_root$hierarchy/.systemd-sysext"
test -f "$fake_root/usr/.systemd-sysext/extensions"
verify_single_mount "$submount" "after refresh"
test -f "$submount/marker"

run_systemd_sysext "$fake_root" unmerge
test ! -e "$fake_root/usr/.systemd-sysext"
verify_single_mount "$submount" "after unmerge"
test -f "$submount/marker"
)

# As above, run once with mounting beneath and once forcing the fallback path
for mount_beneath in yes no; do
( init_trap
: "Refresh of a mutable merge switches to a new work directory and removes the old one (mount beneath: $mount_beneath)"
# shellcheck disable=SC2031 # The setting is meant to be confined to this test case's subshell
export SYSTEMD_SYSEXT_MOUNT_BENEATH=$mount_beneath
fake_root=${roots_dir:+"$roots_dir/refresh-mutable-work-dir-$mount_beneath"}
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_data_dir_usr="$fake_root/var/lib/extensions.mutable/usr"

[[ "$FSTYPE" == "fuseblk" ]] && exit 0

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
# The extension-release file makes /usr/ mutable as well, clean up its extensions.mutable directory, too
prepend_trap "rm -rf ${extension_data_dir_usr@Q}"

# Counts the work directories of all hierarchies, i.e. of /usr/ and of $hierarchy
count_work_dirs() {
    find "$fake_root/var/lib/extensions.mutable" -mindepth 1 -maxdepth 1 -name '.systemd-*-workdir*' | wc -l
}

verify_work_dirs() {
    local expected=${1:?}
    local message=${2:?}
    local n

    n=$(count_work_dirs)
    if [ "$n" != "$expected" ]; then
        echo >&2 "Expected $expected work directories $message, found $n"
        exit 1
    fi
}

run_systemd_sysext "$fake_root" --mutable=yes merge
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
WORKDIR1=$(<"$fake_root$hierarchy/.systemd-sysext/work_dir")
test -d "$fake_root/$WORKDIR1"
# The mounted overlayfs must use the work directory recorded in the metadata
extension_verify_mount_option "$fake_root$hierarchy" "workdir=$fake_root/$WORKDIR1"
verify_work_dirs 2 "after merge"

# A failed refresh must leave the work directory of the existing merge alone, and must not leave the work
# directory it created for the new overlayfs behind
if SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS=nonexistent_option=1 run_systemd_sysext "$fake_root" --mutable=yes refresh --always-refresh=yes; then
    echo >&2 "Mutable refresh with an invalid overlayfs mount option unexpectedly succeeded"
    exit 1
fi
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -d "$fake_root/$WORKDIR1"
verify_work_dirs 2 "after failed refresh"

# Make the refresh fail on $hierarchy only, after /usr/ was assembled already: with a tmpfs on the write
# routing directory no work directory can be placed next to it (it must be on the same file system), so the
# work directory already created for /usr/ must be removed again.
mount -t tmpfs -o mode=0755 tmpfs "$extension_data_dir"
prepend_trap "umount -l ${extension_data_dir@Q} 2>/dev/null || true"
if run_systemd_sysext "$fake_root" --mutable=yes refresh --always-refresh=yes; then
    echo >&2 "Mutable refresh with a write routing directory on a different file system unexpectedly succeeded"
    exit 1
fi
umount "$extension_data_dir"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -d "$fake_root/$WORKDIR1"
verify_work_dirs 2 "after failed refresh of one hierarchy"

run_systemd_sysext "$fake_root" --mutable=yes refresh --always-refresh=yes
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
WORKDIR2=$(<"$fake_root$hierarchy/.systemd-sysext/work_dir")
if [ "$WORKDIR1" = "$WORKDIR2" ]; then
    echo >&2 "Refresh reused the work directory of the previous merge"
    exit 1
fi
test ! -e "$fake_root/$WORKDIR1"
test -d "$fake_root/$WORKDIR2"
extension_verify_mount_option "$fake_root$hierarchy" "workdir=$fake_root/$WORKDIR2"
verify_work_dirs 2 "after refresh"

run_systemd_sysext "$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
verify_work_dirs 0 "after unmerge"
)
done

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
umount -l /usr/share
test ! -f /usr/share/abc
mount --bind /tmp/foo /usr/share
systemd-sysext unmerge
test ! -f /usr/lib/systemd/system/some_file
mountpoint /usr/share
umount -l /usr/share
rm -f /var/lib/extensions/app0.raw

exit 0
