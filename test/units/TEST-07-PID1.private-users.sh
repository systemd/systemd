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
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/uid_map | tr -d "\n")" == "         0          0          1         1          1 4294967294"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/gid_map | tr -d "\n")" == "         0          0          1         1          1 4294967294"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/setgroups)" == "allow"'
