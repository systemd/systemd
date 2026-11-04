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
    local -a extra_args=()

    if [[ "$scope" == "user" ]]; then
        extra_args+=("--user" "--machine" "testuser@")
        USER_UNITS+=("$unit")
    else
        SYSTEM_UNITS+=("$unit")
    fi

    if [[ "$unit" == *.scope ]]; then
        systemd-run --quiet --scope --unit="$unit" "${extra_args[@]}" -- \
            bash -c 'sleep infinity </dev/null >/dev/null 2>&1 &'
    else
        systemd-run --quiet --unit="$unit" -p Type=notify -p NotifyAccess=all \
            "${extra_args[@]}" -- bash -c 'systemd-notify --ready; exec sleep infinity'
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

# Units that follow the xdg-app naming convention end up in a corresponding slice
spawn_unit user app-com.example.BasicApp.service
assert_eq "$(systemctl_user show -P Slice app-com.example.BasicApp.service)" "app-com.example.BasicApp.slice"

# Templated services work
spawn_unit user app-com.example.TemplateApp@123.service
assert_eq "$(systemctl_user show -P Slice app-com.example.TemplateApp@123.service)" "app-com.example.TemplateApp.slice"

# All instances of templated services end up in the same slice
spawn_unit user app-com.example.TemplateApp@456.service
assert_eq "$(systemctl_user show -P Slice app-com.example.TemplateApp@456.service)" "app-com.example.TemplateApp.slice"

# Ditto for scopes
spawn_unit user app-com.example.ScopeApp-123.scope
assert_eq "$(systemctl_user show -P Slice app-com.example.ScopeApp-123.scope)" "app-com.example.ScopeApp.slice"
spawn_unit user app-com.example.ScopeApp-456.scope
assert_eq "$(systemctl_user show -P Slice app-com.example.ScopeApp-456.scope)" "app-com.example.ScopeApp.slice"

# Make sure the escaping works right
spawn_unit user "app-com.example.Needs\\x2dEscape.service"
assert_eq "$(systemctl_user show -P Slice "app-com.example.Needs\\x2dEscape.service")" "app-com.example.Needs\\x2dEscape.slice"

# system units don't participate in the xdg-app naming convention
system_test_case() {
    local unit="$1" slice="${2:-system.slice}"
    spawn_unit system "$unit"
    assert_eq "$(systemctl show -P Slice "$unit")" "$slice"
}

system_test_case test-not-app.service
system_test_case app-com.example.BasicApp.service
system_test_case app-com.example.TemplateApp@123.service "system-app\\x2dcom.example.TemplateApp.slice"
system_test_case app-com.example.TemplateApp@456.service "system-app\\x2dcom.example.TemplateApp.slice"
system_test_case app-com.example.ScopeApp-123.scope
system_test_case app-com.example.ScopeApp-456.scope
