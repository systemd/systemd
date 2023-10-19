#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Make sure the unit's exec context matches its configuration
# See: https://github.com/systemd/systemd/pull/29552

# Even though hidepid= was introduced in kernel 3.3, we support only
# the post 5.8 implementation that allows us to apply the option per-instance,
# instead of the whole namespace. To distinguish between these two implementations
# lets check if we can mount procfs with a named value (e.g. hidepid=off), since
# support for this was introduced in the same commit as the per-instance stuff
proc_supports_option() {
    local option="${1:?}"
    local proc_tmp ec

    proc_tmp="$(mktemp -d)"
    mount -t proc -o "$option" proc "$proc_tmp" && ec=0 || ec=$?
    mountpoint -q "$proc_tmp" && umount -q "$proc_tmp"
    rm -rf "$proc_tmp"

    return $ec
}

# In coverage builds we disable ProtectSystem= and ProtectHome= via a service.d
# dropin in /etc. This dropin has, unfortunately, higher priority than
# the transient stuff from systemd-run. Let's just skip the following tests
# in that case instead of complicating the test setup even more */
if [[ -z "${COVERAGE_BUILD_DIR:-}" ]]; then
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
fi

if proc_supports_option "hidepid=off"; then
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
fi

if proc_supports_option "subset=pid"; then
    systemd-run --wait --pipe -p ProcSubset=pid -p User=testuser \
        bash -xec "test -r /proc/1/comm; test ! -e /proc/cpuinfo"
    systemd-run --wait --pipe -p ProcSubset=all -p User=testuser \
        bash -xec "test -r /proc/1/comm; test -r /proc/cpuinfo"
fi

if ! systemd-detect-virt -cq; then
    systemd-run --wait --pipe -p ProtectKernelLogs=yes -p User=testuser \
        bash -xec "test ! -r /dev/kmsg"
    systemd-run --wait --pipe -p ProtectKernelLogs=no -p User=testuser \
        bash -xec "test -r /dev/kmsg"
fi
