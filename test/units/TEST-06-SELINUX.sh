#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

. /etc/os-release
if ! [[ "$ID" =~ centos|fedora ]]; then
    echo "Skipping because only CentOS and Fedora support SELinux tests" >>/skipped
    exit 77
fi

# Note: ATTOW the following checks should work with both Fedora and upstream reference policy
#       (with or without MCS/MLS)

sestatus

# We should end up in permissive mode
[[ "$(getenforce)" == "Permissive" ]]

# Check PID 1's context
PID1_CONTEXT="$(ps -h -o label 1)"
[[ "$PID1_CONTEXT" =~ ^system_u:system_r:init_t(:s0)?$ ]]
# The same label should be attached to all PID 1's journal messages
journalctl -q -b -p info -n 5 --grep . _SELINUX_CONTEXT="$PID1_CONTEXT"

# Check context on a couple of arbitrarily-selected files/directories
[[ "$(stat --printf %C /run/systemd/journal/)" =~ ^system_u:object_r:(syslogd_runtime_t|syslogd_var_run_t)(:s0)?$ ]]
[[ "$(stat --printf %C /run/systemd/notify)" =~ ^system_u:object_r:(init_runtime_t|init_var_run_t)(:s0)?$ ]]
[[ "$(stat --printf %C /run/systemd/sessions/)" =~ ^system_u:object_r:(systemd_sessions_runtime_t|systemd_logind_sessions_t)(:s0)?$ ]]

# Check if our SELinux-related functionality works
#
# Since the SELinux policies vary wildly, use a context from some existing file
# as our test context
CONTEXT="$(stat -c %C /proc/sys/kernel/core_pattern)"

[[ "$(systemd-run --wait --pipe -p SELinuxContext="$CONTEXT" cat /proc/self/attr/current | tr -d '\0')" == "$CONTEXT" ]]
(! systemd-run --wait --pipe -p SELinuxContext="foo:bar:baz" cat /proc/self/attr/current)
(! systemd-run --wait --pipe -p ConditionSecurity='selinux' false)
systemd-run --wait --pipe -p ConditionSecurity='!selinux' false

NSPAWN_ARGS=(systemd-nspawn -q --volatile=yes --directory=/ --bind-ro=/etc --inaccessible=/etc/machine-id)
[[ "$("${NSPAWN_ARGS[@]}" cat /proc/self/attr/current | tr -d '\0')" != "$CONTEXT" ]]
[[ "$("${NSPAWN_ARGS[@]}" --selinux-context="$CONTEXT" cat /proc/self/attr/current | tr -d '\0')" == "$CONTEXT" ]]
[[ "$("${NSPAWN_ARGS[@]}" stat --printf %C /run)" != "$CONTEXT" ]]
[[ "$("${NSPAWN_ARGS[@]}" --selinux-apifs-context="$CONTEXT" stat --printf %C /run)" == "$CONTEXT" ]]
[[ "$("${NSPAWN_ARGS[@]}" --selinux-apifs-context="$CONTEXT" --tmpfs=/tmp stat --printf %C /tmp)" == "$CONTEXT" ]]

if [[ -n "${TEST_SELINUX_CHECK_AVCS:-}" ]] && ((TEST_SELINUX_CHECK_AVCS)); then
    (! journalctl -t audit -g AVC -o cat)
fi

touch /testok
