#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Make sure the unit's exec context matches its configuration
# See: https://github.com/systemd/systemd/pull/29552

systemd-run --wait --pipe -p ProtectSystem=yes \
    bash -xec "test ! -w /usr; test ! -w /boot; test -w /etc; test -w /var"
systemd-run --wait --pipe -p ProtectSystem=full \
    bash -xec "test ! -w /usr; test ! -w /boot; test ! -w /etc; test -w /var"
systemd-run --wait --pipe -p ProtectSystem=strict \
    bash -xec "test ! -w /; test ! -w /etc; test ! -w /var; test -w /dev; test -w /proc"
systemd-run --wait --pipe -p ProtectSystem=no \
    bash -xec "test -w /; test -w /etc; test -w /var; test -w /dev; test -w /proc"

MARK="$(mktemp /root/.exec-context.XXX)"
systemd-run --wait --pipe -p ProtectHome=yes \
    bash -xec "test ! -w /home; test ! -w /root; test ! -w /run/user; test ! -e $MARK"
systemd-run --wait --pipe -p ProtectHome=read-only \
    bash -xec "test ! -w /home; test ! -w /root; test ! -w /run/user; test -e $MARK"
systemd-run --wait --pipe -p ProtectHome=tmpfs \
    bash -xec "test -w /home; test -w /root; test -w /run/user; test ! -e $MARK"
systemd-run --wait --pipe -p ProtectHome=no \
    bash -xec "test -w /home; test -w /root; test -w /run/user; test -e $MARK"
rm -f "$MARK"

systemd-run --wait --pipe -p ProtectProc=noaccess -p User=testuser \
    bash -xec 'test -e /proc/1; test ! -r /proc/1; test -r /proc/$$$$/comm'
systemd-run --wait --pipe -p ProtectProc=invisible -p User=testuser \
    bash -xec 'test ! -e /proc/1; test -r /proc/$$$$/comm'
systemd-run --wait --pipe -p ProtectProc=ptraceable -p User=testuser \
    bash -xec 'test ! -e /proc/1; test -r /proc/$$$$/comm'
systemd-run --wait --pipe -p ProtectProc=ptraceable -p User=testuser -p AmbientCapabilities=CAP_SYS_PTRACE \
    bash -xec 'test -r /proc/1; test -r /proc/$$$$/comm'
systemd-run --wait --pipe -p ProtectProc=default -p User=testuser \
    bash -xec 'test -r /proc/1; test -r /proc/$$$$/comm'

systemd-run --wait --pipe -p ProcSubset=pid -p User=testuser \
    bash -xec "test -r /proc/1/comm; test ! -e /proc/cpuinfo"
systemd-run --wait --pipe -p ProcSubset=all -p User=testuser \
    bash -xec "test -r /proc/1/comm; test -r /proc/cpuinfo"

if ! systemd-detect-virt -cq; then
    systemd-run --wait --pipe -p ProtectKernelLogs=yes -p User=testuser \
        bash -xec "test ! -r /dev/kmsg"
    systemd-run --wait --pipe -p ProtectKernelLogs=no -p User=testuser \
        bash -xec "test -r /dev/kmsg"
fi
