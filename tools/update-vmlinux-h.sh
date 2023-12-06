#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

cd "${1:?}"

exec bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
