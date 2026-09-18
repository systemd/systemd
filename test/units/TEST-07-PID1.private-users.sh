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

# Regression test for https://github.com/systemd/systemd/issues/41994. Use more than the old
# three-GID limit and verify the GIDs in both the process credentials and the user namespace map.
supplementary_groups=()
supplementary_gids=()
for i in {0..3}; do
        group="test-07-private-users-$i"
        groupadd "$group"
        supplementary_groups+=("$group")
        supplementary_gids+=("$(getent group "$group" | cut -d: -f3)")
done
systemd-run -p PrivateUsers=yes -p DynamicUser=yes -p SupplementaryGroups="${supplementary_groups[*]}" \
        --wait bash -euxc '
                for gid; do
                        id -G | tr " " "\n" | grep -x "$gid" >/dev/null
                        grep -E "^[[:space:]]+$gid[[:space:]]+$gid[[:space:]]+1$" /proc/self/gid_map >/dev/null
                done
        ' -- "${supplementary_gids[@]}"
