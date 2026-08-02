#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

assert_array_contains() {
    local needle="${1:?}"
    local item

    shift
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done

    echo >&2 "FAIL: '$needle' not found"
    return 1
}

# shellcheck disable=SC2329
cleanup() {
    set +e

    rm -f "$rules"
    udevadm control --reload
    udevadm trigger --settle --action change /dev/null /dev/full
    rm -rf /dev/test-udevadm-symlink-query
}

rules="/run/udev/rules.d/99-test-17.symlink-query.rules"

trap cleanup EXIT

mkdir -p "${rules%/*}"
cat >"$rules" <<'EOF'
SUBSYSTEM=="mem", KERNEL=="null", SYMLINK+="test-udevadm-symlink-query/null-a"
SUBSYSTEM=="mem", KERNEL=="null", SYMLINK+="test-udevadm-symlink-query/null-b"
SUBSYSTEM=="mem", KERNEL=="full", SYMLINK+="test-udevadm-symlink-query/full-a"
SUBSYSTEM=="mem", KERNEL=="full", SYMLINK+="test-udevadm-symlink-query/full-b"
EOF
udevadm control --reload
udevadm trigger --settle --action change /dev/null /dev/full

read -r -a null_links < <(udevadm info -q symlink /dev/null)
read -r -a full_links < <(udevadm info -q symlink /dev/full)

assert_array_contains "test-udevadm-symlink-query/null-a" "${null_links[@]}"
assert_array_contains "test-udevadm-symlink-query/null-b" "${null_links[@]}"
assert_array_contains "test-udevadm-symlink-query/full-a" "${full_links[@]}"
assert_array_contains "test-udevadm-symlink-query/full-b" "${full_links[@]}"

mapfile -t links_by_value < <(udevadm info -q symlink --value /dev/null /dev/full)
expected_links=("${null_links[@]}" "" "${full_links[@]}" "")
assert_eq "${#links_by_value[@]}" "${#expected_links[@]}"
for ((i = 0; i < ${#expected_links[@]}; i++)); do
    assert_eq "${links_by_value[$i]}" "${expected_links[$i]}"
done

exit 0
