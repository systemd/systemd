#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

FAKE_ROOTS_DIR="$(mktemp -d --tmpdir="" fake-roots-XXX)"

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

prepare_root() {
    local root=${1:?}
    local hierarchy=${2:?}
    local dir

    if [[ -d $root ]]; then
        echo >&2 "Directory $root already exists, possible copy-paste error?"
        exit 1
    fi

    for dir in "$hierarchy" "/usr/lib" "/var/lib/extensions/" "/var/lib/extensions.mutable"; do
        mkdir -p "$root$dir"
    done

    {
        echo "ID=testtest"
        echo "VERSION=1.2.3"
    } >"$root/usr/lib/os-release"
}

prepare_extension_image() {
    local root="${1:?}"
    local hierarchy="${2:?}"
    local ext_dir ext_release name

    name="test-extension"
    ext_dir="$root/var/lib/extensions/$name"
    ext_release="$ext_dir/usr/lib/extension-release.d/extension-release.$name"
    mkdir -p "${ext_release%/*}"
    echo "ID=_any" >"$ext_release"
    mkdir -p "$ext_dir/$hierarchy"
    touch "$ext_dir$hierarchy/preexisting-file-in-extension-image"
}

prepare_extension_mutable_dir() {
    local dir=${1:?}

    mkdir -p "$dir"
    touch "$dir/preexisting-file-in-extensions-mutable"
}

make_read_only() {
    local root="${1:?}"
    local hierarchy="${2:?}"

    mount -o bind,ro "$root$hierarchy" "$root$hierarchy"
}

prepare_hierarchy() {
    local root="${1:?}"
    local hierarchy="${2:?}"

    touch "$root$hierarchy/preexisting-file-in-hierarchy"
}

prepare_read_only_hierarchy() {
    local root="${1:?}"
    local hierarchy="${2:?}"

    prepare_hierarchy "$root" "$hierarchy"
    make_read_only "$root" "$hierarchy"
}

# Extra arguments:
#   -e: check for a preexisting file in extension
#   -h: check for a preexisting file in hierarchy
#   -u: check for a preexisting file in upperdir
extension_verify() {
    local root="${1:?}"
    local hierarchy="${2:?}"
    local message="${3:?}"
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
    local file full_path option

    while getopts "ehu" opt; do
        case "$opt" in
            e|h|u)
                args[$opt]=1
                ;;
            *)
                echo >&2 "Unxexpected option: $opt"
                exit 1
        esac
    done

    echo "${args[@]}"

    for option in "${!option_files_map[@]}"; do
        file="${option_files_map[$option]}"
        full_path="$root$hierarchy/$file"

        if [[ ${args[$option]} -ne 0 ]]; then
            if [[ ! -f "$full_path" ]]; then
                ls -la "$root$hierarchy"
                echo >&2 "Expected file '$file' to exist under $root$hierarchy $message"
                exit 1
            fi
        else
            if [[ -f "$full_path" ]]; then
                ls -la "$root$hierarchy"
                echo >&2 "Expected file '$file' to not exist under $root$hierarchy $message"
                exit 1
            fi
        fi
    done
}

extension_verify_after_merge() (
    set +x

    local root="${1:?}"
    local hierarchy="${2:?}"
    shift 2

    extension_verify "$root" "$hierarchy" "after merge" "$@"
)

extension_verify_after_unmerge() (
    set +x

    local root="${1:?}"
    local hierarchy="${2:?}"
    shift 2

    extension_verify "$root" "$hierarchy" "after unmerge" "$@"
)

# General systemd-sysext tests

: "No extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled by default, read-only merged"
fake_root="$FAKE_ROOTS_DIR/simple-read-only-with-read-only-hierarchy"
hierarchy=/usr

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")


: "No extension data in /var/lib/extensions.mutable/…, mutable hierarchy, mutability disabled by default, read-only merged"
fake_root="$FAKE_ROOTS_DIR/simple-read-only-with-mutable-hierarchy"
hierarchy=/usr

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root$hierarchy/should-succeed-on-mutable-fs"

SYSTEMD_SYSEXT_HIERARCHIEe="$hierarchy" systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
touch "$fake_root$hierarchy/should-succeed-on-mutable-fs-again"


: "No extension data in /var/lib/extensions.mutable/…, no hierarchy either, mutability disabled by default, read-only merged"
fake_root="$FAKE_ROOTS_DIR/simple-read-only-with-missing-hierarchy"
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
rmdir "$fake_root/$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"


: "No extension data in /var/lib/extensions.mutable/…, empty hierarchy, mutability disabled by default, read-only merged"
fake_root="$FAKE_ROOTS_DIR/simple-read-only-with-empty-hierarchy"
hierarchy=/opt

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
make_read_only "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled by default, read-only merged"
fake_root="$FAKE_ROOTS_DIR/simple-mutable-with-read-only-hierarchy-disabled"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-be-read-only")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h

: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, auto-mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/simple-mutable-with-read-only-hierarchy"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data in /var/lib/extensions.mutable/…, missing hierarchy, auto-mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/simple-mutable-with-missing-hierarchy"
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
rmdir "$fake_root/$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -u
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data in /var/lib/extensions.mutable/…, empty hierarchy, auto-mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/simple-mutable-with-empty-hierarchy"
hierarchy=/opt
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
make_read_only "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -u
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy"
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "/var/lib/extensions.mutable/… is a symlink to other dir, R/O hierarchy, auto-mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/mutable-symlink-with-read-only-hierarchy"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root/upperdir"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "/var/lib/extensions.mutable/… is a symlink to the hierarchy itself, mutable hierarchy, auto-mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/mutable-self-upper"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
touch "$fake_root$hierarchy/preexisting-file-in-hierarchy"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h -u
test -f "$extension_data_dir/now-is-mutable"
test -f "$extension_real_dir/now-is-mutable"


: "/var/lib/extensions.mutable/… is a symlink to the hierarchy itself, R/O hierarchy, auto-mutability, expected fail"
fake_root="$FAKE_ROOTS_DIR/failure-self-upper-ro"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"

(! SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge)


: "/var/lib/extensions.mutable/… is a dangling symlink, auto-mutability, read-only merged"
fake_root="$FAKE_ROOTS_DIR/read-only-mutable-dangling-symlink"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
ln -sfTr "/should/not/exist/" "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "/var/lib/extensions.mutable/… exists but ignored, mutability disabled explicitly, read-only merged"
fake_root="$FAKE_ROOTS_DIR/disabled"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=no merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "/var/lib/extensions.mutable/… exists but is imported instead, read-only merged"
fake_root="$FAKE_ROOTS_DIR/imported"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=import merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "/var/lib/extensions.mutable/… doesn't exists, mutability enabled, mutable merged"
fake_root="$FAKE_ROOTS_DIR/enabled"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")
test ! -d "$extension_data_dir"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=yes merge
test -d "$extension_data_dir"
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "/var/lib/extensions.mutable/… doesn't exists, auto-mutability, read-only merged"
fake_root="$FAKE_ROOTS_DIR/simple-read-only-explicit"
hierarchy=/usr

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=auto merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "/var/lib/extensions.mutable/… doesn't exists, mutability enabled through env var, mutable merged"
fake_root="$FAKE_ROOTS_DIR/enabled-env-var"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")
test ! -d "$extension_data_dir"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=yes systemd-sysext --root="$fake_root" merge
test -d "$extension_data_dir"
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=yes systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "/var/lib/extensions.mutable/… doesn't exists, auto-mutability enabled through env var, read-only merged"
fake_root="$FAKE_ROOTS_DIR/read-only-auto-env-var"
hierarchy=/usr

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=auto systemd-sysext --root="$fake_root" --mutable=auto merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=auto systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, auto-mutability enabled through env var, mutable merged"
fake_root="$FAKE_ROOTS_DIR/auto-mutable-env-var"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=auto systemd-sysext --root="$fake_root" merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=auto systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability disabled through env var, read-only merged"
fake_root="$FAKE_ROOTS_DIR/env-var-disabled"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=no systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-be-read-only")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=no systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "/var/lib/extensions.mutable/… exists but is imported through env var, read-only merged"
fake_root="$FAKE_ROOTS_DIR/imported-env-var"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=import systemd-sysext --root="$fake_root" merge
(! touch "$fake_root$hierarchy/should-still-fail-on-read-only-fs")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=import systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, mutability enabled through env var but overridden via CLI option, read-only merged"
fake_root="$FAKE_ROOTS_DIR/env-var-overridden"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=yes systemd-sysext --root="$fake_root" --mutable=no merge
(! touch "$fake_root$hierarchy/should-be-read-only")
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=yes systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/ephemeral"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=ephemeral merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test ! -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral mutability through env var, mutable merged"
fake_root="$FAKE_ROOTS_DIR/ephemeral-env-var"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral systemd-sysext --root="$fake_root" merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h
test ! -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral import mutability, mutable merged"
fake_root="$FAKE_ROOTS_DIR/ephemeral-import"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

# run systemd-sysext
SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=ephemeral-import merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test ! -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data in /var/lib/extensions.mutable/…, R/O hierarchy, ephemeral import mutability through env var, mutable merged"
fake_root="$FAKE_ROOTS_DIR/ephemeral-import-env-var"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_data_dir"
prepare_read_only_hierarchy "$fake_root" "$hierarchy"
(! touch "$fake_root$hierarchy/should-fail-on-read-only-fs")

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral-import systemd-sysext --root="$fake_root" merge
touch "$fake_root$hierarchy/now-is-mutable"
extension_verify_after_merge "$fake_root" "$hierarchy" -e -h -u
test ! -f "$extension_data_dir/now-is-mutable"

SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" SYSTEMD_SYSEXT_MUTABLE_MODE=ephemeral-import systemd-sysext --root="$fake_root" unmerge
extension_verify_after_unmerge "$fake_root" "$hierarchy" -h
test ! -f "$extension_data_dir/now-is-mutable"
test ! -f "$fake_root$hierarchy/now-is-mutable"


: "Extension data pointing to mutable hierarchy, ephemeral import mutability, expected fail"
fake_root="$FAKE_ROOTS_DIR/ephemeral-import-self"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepare_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root$hierarchy/should-succeed-on-read-only-fs"

(! SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=ephemeral-import merge)


: "Extension data pointing to mutable hierarchy,  import mutability, expected fail"
fake_root="$FAKE_ROOTS_DIR/import-self"
hierarchy=/usr
extension_data_dir="$fake_root/var/lib/extensions.mutable$hierarchy"
extension_real_dir="$fake_root$hierarchy"

prepare_root "$fake_root" "$hierarchy"
prepare_extension_image "$fake_root" "$hierarchy"
prepare_extension_mutable_dir "$extension_real_dir"
ln -sfTr "$extension_real_dir" "$extension_data_dir"
prepare_hierarchy "$fake_root" "$hierarchy"
touch "$fake_root$hierarchy/should-succeed-on-read-only-fs"

(! SYSTEMD_SYSEXT_HIERARCHIES="$hierarchy" systemd-sysext --root="$fake_root" --mutable=import merge)

exit 0
