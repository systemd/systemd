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

# Regression test for https://github.com/systemd/systemd/issues/41994:
# SupplementaryGroups= IDs must remain visible inside a PrivateUsers=yes
# user namespace rather than being collapsed to the kernel's overflow GID
# (nogroup). Picks a stable, low-numbered system group ("bin", GID 2) so
# the assertion does not depend on /etc/group contents.
systemd-run -p PrivateUsers=yes -p DynamicUser=yes -p SupplementaryGroups=2 --wait \
        bash -c 'id -G | tr " " "\n" | grep -x 2 >/dev/null'
systemd-run -p PrivateUsersEx=self -p DynamicUser=yes -p SupplementaryGroups=2 --wait \
        bash -c 'id -G | tr " " "\n" | grep -x 2 >/dev/null'
# The matching map line should be present in gid_map (formatted with %10u fields).
systemd-run -p PrivateUsers=yes -p DynamicUser=yes -p SupplementaryGroups=2 --wait \
        bash -c 'grep -E "^[[:space:]]+2[[:space:]]+2[[:space:]]+1$" /proc/self/gid_map >/dev/null'
