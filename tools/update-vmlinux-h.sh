#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

# This updates the shipped vmlinux.h for the local architecture

cd "${1:?}"

mkdir -p "${2:?}"

exec bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${2:?}"/vmlinux.h
