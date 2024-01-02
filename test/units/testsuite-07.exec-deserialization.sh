#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

setup_base_unit() {
    local unit_path="${1:?}"
    local log_file="${2:?}"
    local unit_name="${unit_path##*/}"

    cat >"$unit_path" <<EOF
[Service]
Type=oneshot
ExecStart=sleep 3
ExecStart=bash -c "echo foo >>$log_file"
EOF
    systemctl daemon-reload

    systemctl --job-mode=replace --no-block start "$unit_name"
    # Wait until the unit leaves the "inactive" state
    timeout 5s bash -xec "while [[ \"\$(systemctl show -P ActiveState $unit_name)\" == inactive ]]; do sleep .1; done"
    # Sleep for 1 second from the unit start to get well "into" the first (or second) ExecStart= directive
    sleep 1
}

check_output() {
    local unit_name="${1:?}"
    local log_file="${2:?}"
    local expected="${3?}"
    local unit_name="${unit_path##*/}"

    # Wait until the unit becomes inactive before checking the log
    timeout 10s bash -xec "while [[ \"\$(systemctl show -P ActiveState $unit_name)\" != inactive ]]; do sleep .5; done"

    diff "$log_file" <(echo -ne "$expected")
}

testcase_no_change() {
    local unit_path log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-no-change-XXX.service)"
    log_file="$(mktemp)"

    setup_base_unit "$unit_path" "$log_file"

    # Simple sanity test without any reordering shenanignans, to check if the base unit works as expected.
    check_output "$unit_path" "$log_file" "foo\n"

    rm -f "$unit_path" "$log_file"
}

testcase_swapped() {
    local unit_path log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-swapped-XXX.service)"
    log_file="$(mktemp)"

    setup_base_unit "$unit_path" "$log_file"

    # Swap the two ExecStart= lines.
    #
    # Since we should be in the first "sleep" of the base unit, after replacing the unit with the following
    # one we should continue running from the respective "ExecStart=sleep 3" line, which is now the last
    # one, resulting no output in the final log file.
    cat >"$unit_path" <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "echo foo >>$log_file"
ExecStart=sleep 3
EOF
    systemctl daemon-reload

    check_output "$unit_path" "$log_file" ""

    rm -f "$unit_path" "$log_file"
}

testcase_added_before() {
    local unit_path log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-added-before-XXX.service)"
    log_file="$(mktemp)"

    setup_base_unit "$unit_path" "$log_file"

    # Add one new ExecStart= before the existing ones.
    #
    # Since, after reload, we should continue running from the "sleep 3" statement, the newly added "echo
    # bar" one will have no efect and we should end up with the same output as in the previous case.
    cat >"$unit_path" <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "echo bar >>$log_file"
ExecStart=sleep 3
ExecStart=bash -c "echo foo >>$log_file"
EOF
    systemctl daemon-reload

    check_output "$unit_path" "$log_file" "foo\n"

    rm -f "$unit_path" "$log_file"
}

testcase_added_after() {
    local unit_path log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-added-after-XXX.service)"
    log_file="$(mktemp)"

    setup_base_unit "$unit_path" "$log_file"

    # Add an ExecStart= line after the existing ones.
    #
    # Same case as above, except the newly added ExecStart= should get executed, as it was added after the
    # "sleep 3" statement.
    cat >"$unit_path" <<EOF
[Service]
Type=oneshot
ExecStart=sleep 3
ExecStart=bash -c "echo foo >>$log_file"
ExecStart=bash -c "echo bar >>$log_file"
EOF
    systemctl daemon-reload

    check_output "$unit_path" "$log_file" "foo\nbar\n"

    rm -f "$unit_path" "$log_file"
}

testcase_interleaved() {
    local unit_path log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-interleaved-XXX.service)"
    log_file="$(mktemp)"

    setup_base_unit "$unit_path" "$log_file"

    # Combination of the two previous cases.
    cat >"$unit_path" <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "echo baz >>$log_file"
ExecStart=sleep 3
ExecStart=bash -c "echo foo >>$log_file"
ExecStart=bash -c "echo bar >>$log_file"
EOF
    systemctl daemon-reload

    check_output "$unit_path" "$log_file" "foo\nbar\n"

    rm -f "$unit_path" "$log_file"
}

testcase_removal() {
    local unit_path log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-removal-XXX.service)"
    log_file="$(mktemp)"

    setup_base_unit "$unit_path" "$log_file"

    # Remove the currently executed ExecStart= line.
    #
    # In this case we completely drop the currently excuted "sleep 3" statement, so after reload systemd
    # should complain that the currently executed command vanished and simply finish executing the unit,
    # resulting in an empty log.
    cat >"$unit_path" <<EOF
[Service]
Type=oneshot
ExecStart=bash -c "echo bar >>$log_file"
ExecStart=bash -c "echo baz >>$log_file"
EOF
    systemctl daemon-reload

    check_output "$unit_path" "$log_file" ""

    rm -f "$unit_path" "$log_file"
}

testcase_issue_6533() {
    local unit_path unit_name log_file

    unit_path="$(mktemp /run/systemd/system/test-deserialization-issue-6533-XXX.service)"
    unit_name="${unit_path##*/}"
    log_file="$(mktemp)"

    cat >"$unit_path" <<EOF
[Service]
Type=simple
ExecStart=/bin/sleep 5
EOF
    systemctl daemon-reload

    systemctl --job-mode=replace --no-block start "$unit_name"
    sleep 2

    # Make sure we try to execute the next command only for oneshot services, as for other types we allow
    # only one ExecStart= directive.
    #
    # See: https://github.com/systemd/systemd/issues/6533
    cat >"$unit_path" <<EOF
[Service]
Type=simple
ExecStart=/bin/sleep 5
ExecStart=bash -c "echo foo >>$log_file"
EOF
    systemctl daemon-reload

    check_output "$unit_path" "$log_file" ""
    (! journalctl -b --grep "Freezing execution" _PID=1)
}

mkdir -p /run/systemd/system/
run_testcases
systemctl daemon-reload
