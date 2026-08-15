#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! cgroupfs_supports_user_xattrs; then
    echo "CGroup does not support user xattrs, skipping LogFilterPatterns= tests."
    exit 0
fi

# Unfortunately, journalctl -I/--invocation= is unstable when debug logging is enabled on service manager.
SAVED_LOG_LEVEL=$(systemctl log-level)
systemctl log-level info

NEEDS_RELOAD=

add_logs_filtering_override() {
    local unit="${1:?}"
    local override_name="${2:?}"
    local log_filter="${3:-}"

    mkdir -p "/run/systemd/system/$unit.d/"
    echo -ne "[Service]\nLogFilterPatterns=$log_filter" >"/run/systemd/system/$unit.d/$override_name.conf"
    NEEDS_RELOAD=1
}

run_service_and_fetch_logs() {
    local unit="${1:?}"

    if [[ -n "$NEEDS_RELOAD" ]]; then
        systemctl daemon-reload
        NEEDS_RELOAD=
    fi

    systemctl start "$unit"
    journalctl --sync
    journalctl -q -u "$unit" -I -p notice
}

at_exit() {
    rm -rf /run/systemd/system/{logs-filtering,delegated-cgroup-filtering}.service.d
    systemctl daemon-reload
}

trap at_exit EXIT

test_service() {
    service="${1:?}"

    # Accept all log messages
    add_logs_filtering_override "$service" "00-reset" ""
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "01-allow-all" ".*"
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    # Discard all log messages
    add_logs_filtering_override "$service" "02-discard-all" "~.*"
    [[ -z $(run_service_and_fetch_logs "$service") ]]

    # Accept all test messages
    add_logs_filtering_override "$service" "03-reset" ""
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    # Discard all test messages
    add_logs_filtering_override "$service" "04-discard-gg" "~.*gg.*"
    [[ -z $(run_service_and_fetch_logs "$service") ]]

    # Deny filter takes precedence
    add_logs_filtering_override "$service" "05-allow-all-but-too-late" ".*"
    [[ -z $(run_service_and_fetch_logs "$service") ]]

    # Use tilde in a deny pattern
    add_logs_filtering_override "$service" "06-reset" ""
    add_logs_filtering_override "$service" "07-prevent-tilde" "~~more~"
    [[ -z $(run_service_and_fetch_logs "$service") ]]

    # Only allow a pattern that won't be matched
    add_logs_filtering_override "$service" "08-reset" ""
    add_logs_filtering_override "$service" "09-allow-only-non-existing" "non-existing string"
    [[ -z $(run_service_and_fetch_logs "$service") ]]

    # Allow a pattern starting with a tilde
    add_logs_filtering_override "$service" "10-allow-with-escape-char" "\\\\x7emore~"
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "11-reset" ""
    add_logs_filtering_override "$service" "12-allow-with-spaces" "foo bar"
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "13-reset" ""
    add_logs_filtering_override "$service" "14-exclude-head" "~^Logging"
    [[ -z $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "15-reset" ""
    add_logs_filtering_override "$service" "16-exclude-head-no-match" "~^foo"
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "17-reset" ""
    add_logs_filtering_override "$service" "18-include-head" "^Logging"
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "19-reset" ""
    add_logs_filtering_override "$service" "20-include-head-no-match" "^foo"
    [[ -z $(run_service_and_fetch_logs "$service") ]]
}

test_delegate() {
    local service="${1:?}"

    add_logs_filtering_override "$service" "00-allow-all" ".*"
    [[ -n $(run_service_and_fetch_logs "$service") ]]

    add_logs_filtering_override "$service" "01-discard-hello" "~hello"
    [[ -z $(run_service_and_fetch_logs "$service") ]]
}

test_service logs-filtering.service
test_service logs-filtering-syslog.service
test_delegate delegated-cgroup-filtering.service

systemctl log-level "$SAVED_LOG_LEVEL"
