#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemd-run -p PrivateUsers=yes --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0          1"'
systemd-run -p PrivateUsers=yes --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0          1"'
systemd-run -p PrivateUsersEx=yes --wait bash -c 'test "$(cat /proc/self/setgroups)" == "deny"'
systemd-run -p PrivateUsersEx=self --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0          1"'
systemd-run -p PrivateUsersEx=self --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0          1"'
systemd-run -p PrivateUsersEx=self --wait bash -c 'test "$(cat /proc/self/setgroups)" == "deny"'
systemd-run -p PrivateUsersEx=identity --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0      65536"'
systemd-run -p PrivateUsersEx=identity --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0      65536"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0 4294967295"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0 4294967295"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/setgroups)" == "allow"'

# Regression test for https://github.com/systemd/systemd/issues/41994. Verify that supplementary GIDs
# are mapped for both dynamic and static users and that duplicate mappings are suppressed.
if ! command -v groupadd >/dev/null || ! command -v useradd >/dev/null; then
    echo "groupadd or useradd is not installed, skipping the supplementary group checks."
    exit 0
fi

test_user="test-07-private-users"
groups=()
created_groups=()

cleanup() {
    set +e
    userdel "$test_user"
    for group in "${created_groups[@]}"; do
        groupdel "$group"
    done
}
trap cleanup EXIT

for i in {0..3}; do
    group="test-07-private-users-$i"
    groups+=("$group")
    if ! getent group "$group" >/dev/null; then
        groupadd "$group"
        created_groups+=("$group")
    fi
done

gids=()
for group in "${groups[@]}"; do
    gids+=("$(getent group "$group" | cut -d: -f3)")
done

verify_groups='count_gid_map_extents() {
    awk -v gid="$1" '\''$1 == gid && $2 == gid && $3 == 1 { n++ } END { print n + 0 }'\'' /proc/self/gid_map
}
test "$(count_gid_map_extents 0)" -eq 1
for gid; do
    test "$(id -G | tr " " "\n" | grep -cx "$gid")" -eq 1
    test "$(count_gid_map_extents "$gid")" -eq 1
done'

systemd-run --wait \
    -p PrivateUsers=yes \
    -p DynamicUser=yes \
    -p SupplementaryGroups="${groups[0]} ${groups[1]} ${groups[1]} ${groups[2]} ${groups[3]}" \
    bash -euxc "$verify_groups" -- "${gids[@]}"

getent passwd "$test_user" >/dev/null && userdel "$test_user"
useradd --no-create-home --gid "${groups[0]}" --groups "${groups[1]}" "$test_user"

systemd-run --wait \
    -p PrivateUsers=yes \
    -p User="$test_user" \
    -p Group="${groups[0]}" \
    -p SupplementaryGroups="root ${groups[0]} ${groups[2]} ${groups[2]} ${groups[3]}" \
    bash -euxc "$verify_groups" -- "${gids[@]}"

# Also cover supplementary groups obtained solely from the user database.
systemd-run --wait \
    -p PrivateUsers=yes \
    -p User="$test_user" \
    -p Group="${groups[0]}" \
    bash -euxc "$verify_groups" -- "${gids[0]}" "${gids[1]}"
