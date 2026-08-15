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
value_null_links=()
value_full_links=()
n_separators=0

for link in "${links_by_value[@]}"; do
    if [[ -z "$link" ]]; then
        n_separators=$((n_separators + 1))
        continue
    fi

    case "$n_separators" in
        0)
            value_null_links+=("$link")
            ;;
        1)
            value_full_links+=("$link")
            ;;
        *)
            assert_not_reached
    esac
done

assert_eq "$n_separators" 2
assert_eq "${#value_null_links[@]}" "${#null_links[@]}"
assert_eq "${#value_full_links[@]}" "${#full_links[@]}"

for link in "${null_links[@]}"; do
    assert_array_contains "$link" "${value_null_links[@]}"
done
for link in "${full_links[@]}"; do
    assert_array_contains "$link" "${value_full_links[@]}"
done

exit 0
