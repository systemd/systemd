#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail
set -E

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

CLONESETUP_BIN=/usr/lib/systemd/systemd-clonesetup
# Test clonesetup generator and systemd-clonesetup
# Disable pager usage so interactive/manual runs do not block in `less`.
export SYSTEMD_PAGER=cat
export SYSTEMD_LESS=

create_loop_triplet() {
    local workdir="${1:?}"
    local src_img dst_img meta_img
    local loop_src loop_dst loop_meta

    src_img="$workdir/source.img"
    dst_img="$workdir/dest.img"
    meta_img="$workdir/meta.img"

    truncate -s 32M "$src_img"
    truncate -s 32M "$dst_img"
    truncate -s 8M "$meta_img"

    loop_src="$(losetup --show --find "$src_img")"
    loop_dst="$(losetup --show --find "$dst_img")"
    loop_meta="$(losetup --show --find "$meta_img")"

    # Wait for udev to process new loop devices before they are consumed.
    udevadm settle --timeout=60

    printf '%s %s %s\n' "$loop_src" "$loop_dst" "$loop_meta"
}

cleanup_loop_triplet() {
    local loop_src="${1:-}"
    local loop_dst="${2:-}"
    local loop_meta="${3:-}"

    [[ -n "$loop_src" ]] && losetup -d "$loop_src"
    [[ -n "$loop_dst" ]] && losetup -d "$loop_dst"
    [[ -n "$loop_meta" ]] && losetup -d "$loop_meta"
}

at_exit() {
    set +e

    rm -f /etc/clonetab
    [[ -e /tmp/clonetab.bak ]] && cp -fv /tmp/clonetab.bak /etc/clonetab
    dmsetup remove testclonesetup 2>/dev/null || true

    systemctl daemon-reload
}

at_error() {
    local rc="$?"
    local source="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
    local line="${BASH_LINENO[0]:-0}"
    local func="${FUNCNAME[1]:-main}"

    echo "ERROR: rc=$rc at $source:$line ($func): $BASH_COMMAND" >&2
    return "$rc"
}

trap at_exit EXIT
trap at_error ERR

clonesetup_start_and_check() {
    local volume unit

    volume="${1:?}"
    unit="systemd-clonesetup@$volume.service"

    # The unit existence check should always pass
    [[ "$(systemctl show -P LoadState "$unit")" == loaded ]]
    systemctl list-unit-files "$unit"

    systemctl start "$unit"
    # wait for udev to create /dev/mapper/ node after DM device activation
    udevadm settle --timeout=10
    systemctl status "$unit"
    test -e "/dev/mapper/$volume"
    dmsetup status "$volume"

    systemctl stop "$unit"
    # wait for udev to finish processing so the device node state is in sync
    # before the API returns.
    udevadm settle --timeout=10
    test ! -e "/dev/mapper/$volume"
}

prereq() {
    # Skip when kernel lacks dm-clone (CONFIG_DM_CLONE)
    modprobe dm_clone 2>/dev/null || true
    if [[ ! -d /sys/module/dm_clone ]]; then
        echo "no dm-clone" >/skipped
        exit 77
    fi
    echo "Found required kernel module: dm_clone"
}

prereq

# Backup existing clonetab if any
[[ -e /etc/clonetab ]] && cp -fv /etc/clonetab /tmp/clonetab.bak

# Create test clonetab
clonetab_create() {
    local loop_name="${1:?}"
    local loop_src="${2:?}"
    local loop_dst="${3:?}"
    local loop_meta="${4:?}"
    local loop_options="${5:?}"

    cat >/etc/clonetab <<EOF
# name source dest metadata options
$loop_name $loop_src $loop_dst $loop_meta $loop_options
EOF

}

# Verify --help and --version work
testcase_help_version() {
    $CLONESETUP_BIN --help
    $CLONESETUP_BIN --version
}

test_long_name() {
    local loop_src="${1:?}"
    local loop_dst="${2:?}"
    local loop_meta="${3:?}"

    # Test device name too long — must fail cleanly with ENAMETOOLONG (no DM device created)
    local long_name
    long_name="$(printf 'a%.0s' {1..128})"
    if $CLONESETUP_BIN add "$long_name" "$loop_src" "$loop_dst" "$loop_meta" - ; then
        return 1
    fi

    if [[ -e "/dev/mapper/$long_name" ]]; then
        return 1
    fi
}

test_missing_etc_clonetab() {
    local loop_src="${1:?}"
    local loop_dst="${2:?}"
    local loop_meta="${3:?}"

    # Remove clonetab and reload — generator must produce no units
    rm -f /etc/clonetab
    systemctl daemon-reload
    if systemctl is-enabled systemd-clonesetup@testclonesetup.service; then
        return 1
    fi
    clonetab_create "testclonesetup" "$loop_src" "$loop_dst" "$loop_meta" "-"
    systemctl daemon-reload
}

testcase_idempotent_stop() {
    # Removing a non-existent device must succeed (ENXIO treated as already-inactive)
    $CLONESETUP_BIN remove testclonesetup-nonexistent
}

test_no_device_leak() {
    local loop_dst="${1:?}"
    local loop_meta="${2:?}"

    # Bad source path — DM_TABLE_LOAD must fail and device must be cleaned up
    if $CLONESETUP_BIN add testleak /dev/nonexistent "$loop_dst" "$loop_meta" -; then
        return 1
    fi
    if dmsetup info testleak; then
        return 1
    fi
}

testcase_region_size() {
    local region_workdir region_loop_src region_loop_dst region_loop_meta

    # Use a dedicated loop triplet so metadata from previous test cases cannot affect
    # region_size validation.
    region_workdir="$(mktemp -d)"
    read -r region_loop_src region_loop_dst region_loop_meta < <(create_loop_triplet "$region_workdir")

    # Custom region_size=8K — verify a non-default bytes value is accepted.
    $CLONESETUP_BIN add testregion "$region_loop_src" "$region_loop_dst" "$region_loop_meta" region_size=8K
    dmsetup info testregion
    $CLONESETUP_BIN remove testregion

    cleanup_loop_triplet "$region_loop_src" "$region_loop_dst" "$region_loop_meta"
    rm -rf "$region_workdir"
}

testcase_main_flow() {
    local workdir loop_src loop_dst loop_meta

    workdir="$(mktemp -d)"
    read -r loop_src loop_dst loop_meta < <(create_loop_triplet "$workdir")

    clonetab_create "testclonesetup" "$loop_src" "$loop_dst" "$loop_meta" "-"

    # Run the generator explicitly for coverage
    mkdir -p /tmp/clonesetup-generator.out
    /usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

    # Verify generator output
    test -f /tmp/clonesetup-generator.out/systemd-clonesetup@testclonesetup.service
    test -d /tmp/clonesetup-generator.out/clonesetup.target.requires
    test -d /tmp/clonesetup-generator.out/dev-mapper-testclonesetup.device.requires
    test -f /tmp/clonesetup-generator.out/dev-mapper-testclonesetup.device.d/40-device-timeout.conf

    # Reload systemd to pick up generated units
    systemctl daemon-reload
    systemctl list-unit-files "systemd-clonesetup@*"

    # Check clonesetup.target exists
    systemctl show clonesetup.target

    # Test clonesetup service
    clonesetup_start_and_check testclonesetup

    test_long_name      "$loop_src" "$loop_dst" "$loop_meta"
    test_missing_etc_clonetab  "$loop_src" "$loop_dst" "$loop_meta"
    test_no_device_leak "$loop_dst" "$loop_meta"
    cleanup_loop_triplet "$loop_src" "$loop_dst" "$loop_meta"
    rm -rf "$workdir"
}

testcase_escape_coverage() {
    local workdir loop_src loop_dst loop_meta
    local new_src new_dst new_meta

    workdir="$(mktemp -d)"
    read -r loop_src loop_dst loop_meta < <(create_loop_triplet "$workdir")

    new_src="${loop_src}%foo"
    new_dst="${loop_dst}%bar"
    new_meta="${loop_meta}%baz"
    clonetab_create "testescapepaths" "$new_src" "$new_dst" "$new_meta" "-"

    # Run the generator explicitly for coverage
    rm -rf /tmp/clonesetup-generator.out
    mkdir -p /tmp/clonesetup-generator.out
    /usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

    unit=/tmp/clonesetup-generator.out/systemd-clonesetup@testescapepaths.service
    test -f "$unit"
    exp_src="${new_src//%/%%}"
    exp_dst="${new_dst//%/%%}"
    exp_meta="${new_meta//%/%%}"
    grep -F "$exp_src" "$unit"
    grep -F "$exp_dst" "$unit"
    grep -F "$exp_meta" "$unit"

    cleanup_loop_triplet "$loop_src" "$loop_dst" "$loop_meta"
    rm -rf "$workdir"
}

testcase_invalid_path_rejected() {
    # Space in a device path token should fail parsing/validation and produce no unit.
    cat >/etc/clonetab <<EOF
# name source dest metadata options
testinvalidspace /dev/loop0 /dev/with\ space /dev/loop2 -
EOF

    rm -rf /tmp/clonesetup-generator.out
    mkdir -p /tmp/clonesetup-generator.out
    /usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

    test ! -f /tmp/clonesetup-generator.out/systemd-clonesetup@testinvalidspace.service
}

testcase_invalid_options_rejected() {
    # Double-quote tokens in options should be rejected and produce no unit.
    cat >/etc/clonetab <<EOF
# name source dest metadata options
testinvalidopts /dev/loop0 /dev/loop1 /dev/loop2 ""
EOF

    rm -rf /tmp/clonesetup-generator.out
    mkdir -p /tmp/clonesetup-generator.out
    /usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

    test ! -f /tmp/clonesetup-generator.out/systemd-clonesetup@testinvalidopts.service
}

testcase_backslash() {
    # Backslash in a device path token should fail parsing/validation and produce no unit.
    cat >/etc/clonetab <<EOF
# name source dest metadata options
testbackslash /dev/\x2e\x2e/foo /dev/loop1 /dev/loop2 -
EOF

    rm -rf /tmp/clonesetup-generator.out
    mkdir -p /tmp/clonesetup-generator.out
    /usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

    test ! -f /tmp/clonesetup-generator.out/systemd-clonesetup@testbackslash.service
}

testcase_dot_prefix_name() {
    # when clone name starts with dot(.), generator produces unit names that match what pid1 actually
    # creates. the generator should NOT produce dev-mapper-\x2efoo.device — a unit that never exists.
    cat >/etc/clonetab <<EOF
# name source dest metadata options
.testdot /dev/loop0 /dev/loop1 /dev/loop2 -
EOF

    rm -rf /tmp/clonesetup-generator.out
    mkdir -p /tmp/clonesetup-generator.out
    /usr/lib/systemd/system-generators/systemd-clonesetup-generator /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/ /tmp/clonesetup-generator.out/

    test -d /tmp/clonesetup-generator.out/dev-mapper-.testdot.device.requires
    test ! -d /tmp/clonesetup-generator.out/dev-mapper-\\x2etestdot.device.requires
    grep 'blockdev@dev-mapper-.testdot.target' /tmp/clonesetup-generator.out/systemd-clonesetup@\\x2etestdot.service
}

testcase_omit_options() {
    # Omitting the options field entirely (4-column clonetab) must work the same as passing -.
    # This tests that the service starts successfully — not just that a unit file is generated.
    local workdir loop_src loop_dst loop_meta

    workdir="$(mktemp -d)"
    read -r loop_src loop_dst loop_meta < <(create_loop_triplet "$workdir")

    cat >/etc/clonetab <<EOF
# name source dest metadata (no options column)
testnooptions $loop_src $loop_dst $loop_meta
EOF

    systemctl daemon-reload
    clonesetup_start_and_check testnooptions

    cleanup_loop_triplet "$loop_src" "$loop_dst" "$loop_meta"
    rm -rf "$workdir"
}
run_testcases

touch /testok
