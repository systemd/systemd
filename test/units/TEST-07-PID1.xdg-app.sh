#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemctl_user() {
    systemctl --user --machine "testuser@" "$@"
}

declare -a SYSTEM_UNITS=() USER_UNITS=()

spawn_unit() {
    local scope="$1" unit="$2"
    local -a command=()

    if [[ "$scope" == "user" ]]; then
        command=("runas" "testuser" "systemd-run" "--user")
        USER_UNITS+=("$unit")
    else
        command=("systemd-run")
        SYSTEM_UNITS+=("$unit")
    fi

    command+=("--quiet" "--unit=$unit")

    if [[ "$unit" == *.scope ]]; then
        "${command[@]}" --scope -- \
            bash -c 'sleep infinity </dev/null >/dev/null 2>&1 &'
    else
        "${command[@]}" -p Type=notify -p NotifyAccess=all -- \
            bash -c 'systemd-notify --ready; exec sleep infinity'
    fi
}

at_exit() {
    set +eu

    systemctl stop "${SYSTEM_UNITS[@]}" 2>/dev/null
    systemctl_user stop "${USER_UNITS[@]}" 2>/dev/null
    loginctl disable-linger testuser 2>/dev/null
}

trap at_exit EXIT

loginctl enable-linger testuser
systemctl start "user@$(id -u testuser).service"

# Normal units follow the normal defaults
spawn_unit user test-not-app.service
assert_eq "$(systemctl_user show -P Slice test-not-app.service)" "app.slice"
assert_not_in "App ID" "$(systemctl_user status test-not-app.service)"

# Units that follow the xdg-app naming convention end up in a corresponding slice
spawn_unit user app-com.example.BasicApp.service
assert_eq "$(systemctl_user show -P Slice app-com.example.BasicApp.service)" "app-com.example.BasicApp.slice"
assert_in "App ID: com.example.BasicApp" "$(systemctl_user status app-com.example.BasicApp.service)"

# Templated services work
spawn_unit user app-com.example.TemplateApp@123.service
assert_eq "$(systemctl_user show -P Slice app-com.example.TemplateApp@123.service)" "app-com.example.TemplateApp.slice"
assert_in "App ID: com.example.TemplateApp" "$(systemctl_user status app-com.example.TemplateApp@123.service)"

# All instances of templated services end up in the same slice
spawn_unit user app-com.example.TemplateApp@456.service
assert_eq "$(systemctl_user show -P Slice app-com.example.TemplateApp@456.service)" "app-com.example.TemplateApp.slice"
assert_in "App ID: com.example.TemplateApp" "$(systemctl_user status app-com.example.TemplateApp@456.service)"

# Ditto for scopes
spawn_unit user app-com.example.ScopeApp-123.scope
assert_eq "$(systemctl_user show -P Slice app-com.example.ScopeApp-123.scope)" "app-com.example.ScopeApp.slice"
assert_in "App ID: com.example.ScopeApp" "$(systemctl_user status app-com.example.ScopeApp-123.scope)"
spawn_unit user app-com.example.ScopeApp-456.scope
assert_eq "$(systemctl_user show -P Slice app-com.example.ScopeApp-456.scope)" "app-com.example.ScopeApp.slice"
assert_in "App ID: com.example.ScopeApp" "$(systemctl_user status app-com.example.ScopeApp-456.scope)"

# Make sure the escaping works right
spawn_unit user "app-com.example.Needs\\x2dEscape.service"
assert_eq "$(systemctl_user show -P Slice "app-com.example.Needs\\x2dEscape.service")" "app-com.example.Needs\\x2dEscape.slice"
assert_in "App ID: com.example.Needs-Escape" "$(systemctl_user status "app-com.example.Needs\\x2dEscape.service")"

# system units don't participate in the xdg-app naming convention
system_test_case() {
    local unit="$1" slice="${2:-system.slice}"
    spawn_unit system "$unit"
    assert_eq "$(systemctl show -P Slice "$unit")" "$slice"
    assert_not_in "App ID" "$(systemctl status "$unit")"
}

system_test_case test-not-app.service
system_test_case app-com.example.BasicApp.service
system_test_case app-com.example.TemplateApp@123.service "system-app\\x2dcom.example.TemplateApp.slice"
system_test_case app-com.example.TemplateApp@456.service "system-app\\x2dcom.example.TemplateApp.slice"
system_test_case app-com.example.ScopeApp-123.scope
system_test_case app-com.example.ScopeApp-456.scope
