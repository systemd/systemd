#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

MANAGER_SOCKET="/run/systemd/io.systemd.Manager"

at_exit() {
    local u pid

    for u in "${TRANSIENT_UNITS[@]}"; do
        systemctl stop "$u" 2>/dev/null || true
        systemctl reset-failed "$u" 2>/dev/null || true
    done
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -f "${TEMP_FILES[@]}"
}

setup() {
    TRANSIENT_UNITS=()
    CHILD_PIDS=()
    TEMP_FILES=()
    trap at_exit EXIT
}

defer_transient_cleanup() {
    TRANSIENT_UNITS+=("$1")
}

# Apply-time and dispatch-time validation errors both surface as
# org.varlink.service.InvalidParameter, with the offending field name in the
# response parameters. Use --graceful to treat the expected error as success
# so jq can assert on the dumped parameters JSON directly.
expect_invalid_parameter() {
    local payload="$1" field="$2"
    varlinkctl call --graceful=org.varlink.service.InvalidParameter \
                    "$MANAGER_SOCKET" io.systemd.Unit.StartTransient "$payload" \
        | jq -e --arg f "$field" '.parameter == $f' >/dev/null
}

testcase_basic() {
    setup

    # Basic oneshot transient service
    defer_transient_cleanup varlink-transient-test.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-test.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | grep '"context"' >/dev/null
    echo "$result" | grep '"runtime"' >/dev/null

    # Wait for completion
    timeout 30 bash -c 'until systemctl show -P ActiveState varlink-transient-test.service | grep inactive >/dev/null; do sleep 0.5; done'
    systemctl show -P Result varlink-transient-test.service | grep success >/dev/null

    # With explicit mode
    defer_transient_cleanup varlink-transient-test2.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-test2.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}},"mode":"fail"}')
    echo "$result" | grep '"context"' >/dev/null

    # Multiple ExecStart commands (oneshot allows multiple)
    defer_transient_cleanup varlink-transient-multi.service
    result=$(varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-multi.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"},{"path":"/bin/true"}]}},"notifyJobChanges":true}')
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.Result == "done")' >/dev/null

    # Transient service with Description and RemainAfterExit
    defer_transient_cleanup varlink-transient-desc.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-desc.service","Description":"Test description property","CollectMode":"inactive_or_failed","Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Description == "Test description property"'
    echo "$result" | jq -e '.context.CollectMode == "inactive_or_failed"'
    echo "$result" | jq -e '.context.Service.Type == "oneshot"'
    echo "$result" | jq -e '.context.Service.RemainAfterExit == true'
    echo "$result" | jq -e '.context.Service.ExecStart[0].path == "/bin/true"'
    echo "$result" | jq -e '.runtime'
    systemctl show -P CollectMode varlink-transient-desc.service | grep '^inactive-or-failed$' >/dev/null

    # Transient service with explicit arguments
    defer_transient_cleanup varlink-transient-args.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-args.service","Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/echo","arguments":["/bin/echo","hello"]}]}}}')
    echo "$result" | jq -e '.context'
    echo "$result" | jq -e '.runtime'
    echo "$result" | jq -e '.context.Service.ExecStart[0].path == "/bin/echo"'
    echo "$result" | jq -e '.context.Service.ExecStart[0].arguments == ["/bin/echo", "hello"]'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-args.service; do sleep 0.5; done'

    # Verify that omitting arguments defaults argv[0] to the path
    defer_transient_cleanup varlink-transient-noargs.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-noargs.service","Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Service.ExecStart[0].arguments == ["/bin/true"]'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-noargs.service; do sleep 0.5; done'

    defer_transient_cleanup varlink-transient-bad.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad.service","Service":{"Type":"simple"}}}' \
        "context"
    # Invalid ExecStart path: exercises filename_or_absolute_path_is_valid() in transient_service_apply_properties()
    defer_transient_cleanup varlink-transient-badpath.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-badpath.service","Service":{"Type":"simple","ExecStart":[{"path":""}]}}}' \
        "context.Service.ExecStart.path"

    # Service field declared in the IDL but not yet settable at creation is rejected as PropertyNotSupported,
    # and the offending sub-property is identified
    defer_transient_cleanup varlink-transient-unknown-service.service
    unsupported_service=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-unknown-service.service","Service":{"Type":"oneshot","Restart":"always","ExecStart":[{"path":"/bin/true"}]}}}' 2>&1 || true)
    echo "$unsupported_service" | grep "io.systemd.Unit.PropertyNotSupported"
    echo "$unsupported_service" | grep -F "context.Service.Restart"
}

testcase_dispatch_validation() {
    setup

    defer_transient_cleanup varlink-transient-bad-dispatch.service

    # These inputs pass IDL validation but fail in the property dispatchers.
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-dispatch.service","Exec":{"WorkingDirectory":{"path":"/tmp","home":true}}}}' \
        "context.Exec.WorkingDirectory"
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-dispatch.service","Exec":{"WorkingDirectory":{"path":"","missingOK":true}}}}' \
        "context.Exec.WorkingDirectory.path"
}

testcase_notifications() {
    setup

    # Streaming with notifyJobChanges: should get intermediate state updates and a final result
    # Note: use --slurp + any() rather than 'select() -e' because in jq 1.6 (shipped on
    # CentOS 9) -e checks only the last input record's output, so a select() that filters
    # out the trailing record makes jq exit non-zero even when earlier records match.
    defer_transient_cleanup varlink-transient-test3.service
    result=$(varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-test3.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}},"notifyJobChanges":true}')
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.State == "waiting")' >/dev/null
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.Result == "done")' >/dev/null

    # Fire-and-forget: --more without notify flags should return immediately with context+runtime
    defer_transient_cleanup varlink-transient-fireforget.service
    result=$(varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-fireforget.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}')
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .context)' >/dev/null
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .runtime)' >/dev/null

    # Streaming with notifyUnitChanges: should get unit state change notifications
    defer_transient_cleanup varlink-transient-unitnotify.service
    result=$(varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-unitnotify.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}},"notifyUnitChanges":true}')
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .runtime.ActiveState)' >/dev/null

    # Streaming with both notifyJobChanges and notifyUnitChanges
    defer_transient_cleanup varlink-transient-both.service
    result=$(varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-both.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}},"notifyJobChanges":true,"notifyUnitChanges":true}')
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.State)' >/dev/null
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .runtime.ActiveState)' >/dev/null
    printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.Result == "done")' >/dev/null
}

testcase_exec_properties() {
    setup

    # Exec.WorkingDirectory and Exec.Environment
    defer_transient_cleanup varlink-transient-exec.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-exec.service","Exec":{"WorkingDirectory":{"path":"/tmp","missingOK":false},"Environment":["FOO=old","BAZ=qux","FOO=bar"]},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Exec.WorkingDirectory.path == "/tmp"'
    # Later assignments should override earlier ones, leaving one entry per environment variable.
    echo "$result" | jq -e '.context.Exec.Environment | sort == ["BAZ=qux", "FOO=bar"]'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-exec.service; do sleep 0.5; done'
    systemctl show -P WorkingDirectory varlink-transient-exec.service | grep '^/tmp$' >/dev/null
    systemctl show -P Environment varlink-transient-exec.service | grep 'FOO=bar' >/dev/null
    systemctl show -P Environment varlink-transient-exec.service | grep 'BAZ=qux' >/dev/null

    # WorkingDirectory with missingOK=true (path does not exist but unit still starts)
    defer_transient_cleanup varlink-transient-wd-missing.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-wd-missing.service","Exec":{"WorkingDirectory":{"path":"/nonexistent/path","missingOK":true}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-wd-missing.service; do sleep 0.5; done'

    # WorkingDirectory with home=true, missingOK omitted (defaults to false)
    defer_transient_cleanup varlink-transient-wd-home.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-wd-home.service","Exec":{"WorkingDirectory":{"home":true}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-wd-home.service; do sleep 0.5; done'
    systemctl show -P WorkingDirectory varlink-transient-wd-home.service | grep '^~$' >/dev/null

    # An empty path resets the working directory, matching D-Bus.
    defer_transient_cleanup varlink-transient-wd-empty.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-wd-empty.service","Exec":{"WorkingDirectory":{"path":""}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-wd-empty.service; do sleep 0.5; done'
    [[ -z $(systemctl show -P WorkingDirectory varlink-transient-wd-empty.service) ]]
    systemctl cat varlink-transient-wd-empty.service | grep -Fx 'WorkingDirectory=' >/dev/null

    # Exec.StandardInput/StandardOutput/StandardError enum properties and Exec.TTYPath
    defer_transient_cleanup varlink-transient-stdio.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-stdio.service","Exec":{"StandardInput":"null","StandardOutput":"null","StandardError":"journal","TTYPath":"/dev/tty2"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Exec.StandardInput == "null"'
    echo "$result" | jq -e '.context.Exec.StandardOutput == "null"'
    echo "$result" | jq -e '.context.Exec.StandardError == "journal"'
    echo "$result" | jq -e '.context.Exec.TTYPath == "/dev/tty2"'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-stdio.service; do sleep 0.5; done'
    systemctl show -P StandardInput varlink-transient-stdio.service | grep '^null$' >/dev/null
    systemctl show -P StandardOutput varlink-transient-stdio.service | grep '^null$' >/dev/null
    systemctl show -P StandardError varlink-transient-stdio.service | grep '^journal$' >/dev/null
    systemctl show -P TTYPath varlink-transient-stdio.service | grep '^/dev/tty2$' >/dev/null
    # "null" is also the default for StandardInput=, hence additionally verify it was written explicitly
    fragment=$(systemctl show -P FragmentPath varlink-transient-stdio.service)
    grep '^StandardInput=null$' "$fragment" >/dev/null

    # The combined output types are spelled with a "+" in unit files, but with a "_" in the Varlink IDL (and
    # hence in our own replies). The latter spelling must be accepted, so that replies can be fed back in.
    defer_transient_cleanup varlink-transient-stdio-combined.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-stdio-combined.service","Exec":{"StandardOutput":"kmsg_console","StandardError":"journal_console"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Exec.StandardOutput == "kmsg_console"'
    echo "$result" | jq -e '.context.Exec.StandardError == "journal_console"'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-stdio-combined.service; do sleep 0.5; done'
    systemctl show -P StandardOutput varlink-transient-stdio-combined.service | grep '^kmsg+console$' >/dev/null
    systemctl show -P StandardError varlink-transient-stdio-combined.service | grep '^journal+console$' >/dev/null

    # Exec.User, Exec.Group, Exec.SupplementaryGroups, Exec.Nice
    # The nobody group is different on different distros so resolve here.
    NOBODY_GROUP=$(id -gn nobody)
    defer_transient_cleanup varlink-transient-ids.service
    ids_payload=$(jq -cn --arg g "$NOBODY_GROUP" \
        '{context:{ID:"varlink-transient-ids.service",
                   Exec:{User:"nobody",Group:$g,SupplementaryGroups:[$g],Nice:5},
                   Service:{Type:"oneshot",RemainAfterExit:true,
                            ExecStart:[{path:"/bin/true"}]}}}')
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient "$ids_payload")
    echo "$result" | jq -e '.context.Exec.User == "nobody"'
    echo "$result" | jq --arg g "$NOBODY_GROUP" -e '.context.Exec.Group == $g'
    echo "$result" | jq --arg g "$NOBODY_GROUP" -e '.context.Exec.SupplementaryGroups == [$g]'
    echo "$result" | jq -e '.context.Exec.Nice == 5'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-ids.service; do sleep 0.5; done'
    systemctl show -P User varlink-transient-ids.service | grep '^nobody$' >/dev/null
    systemctl show -P Group varlink-transient-ids.service | grep "^${NOBODY_GROUP}$" >/dev/null
    systemctl show -P SupplementaryGroups varlink-transient-ids.service | grep "${NOBODY_GROUP}" >/dev/null
    systemctl show -P Nice varlink-transient-ids.service | grep '^5$' >/dev/null

    # Exec.PAMName
    defer_transient_cleanup varlink-transient-pam.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-pam.service","Exec":{"PAMName":"systemd-run0"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Exec.PAMName == "systemd-run0"'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-pam.service; do sleep 0.5; done'
    systemctl show -P PAMName varlink-transient-pam.service | grep '^systemd-run0$' >/dev/null

    # Exec.OOMScoreAdjust, Exec.UMask, Exec.NoNewPrivileges, Exec.MemoryDenyWriteExecute
    # (int+validator, mode_t, two tristate-bool shapes)
    defer_transient_cleanup varlink-transient-procctl.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-procctl.service","Exec":{"OOMScoreAdjust":250,"UMask":18,"NoNewPrivileges":true,"MemoryDenyWriteExecute":true},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Exec.OOMScoreAdjust == 250'
    echo "$result" | jq -e '.context.Exec.UMask == 18'
    echo "$result" | jq -e '.context.Exec.NoNewPrivileges == true'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-procctl.service; do sleep 0.5; done'
    systemctl show -P OOMScoreAdjust varlink-transient-procctl.service | grep '^250$' >/dev/null
    systemctl show -P UMask varlink-transient-procctl.service | grep '^0022$' >/dev/null
    systemctl show -P NoNewPrivileges varlink-transient-procctl.service | grep '^yes$' >/dev/null
    systemctl show -P MemoryDenyWriteExecute varlink-transient-procctl.service | grep '^yes$' >/dev/null

    # Exec.RootHashPath / Exec.RootHashSignaturePath: the unit-file directive must be
    # "RootHash=" / "RootHashSignature=" (not the JSON name), otherwise the next daemon-reload
    # would drop the setting as an unknown key.
    defer_transient_cleanup varlink-transient-roothash.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-roothash.service","Exec":{"RootHashPath":"/etc/hostname","RootHashSignaturePath":"/etc/machine-id"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}' >/dev/null
    fragment=$(systemctl show -P FragmentPath varlink-transient-roothash.service)
    test -n "$fragment"
    grep '^RootHash=/etc/hostname$'          "$fragment" >/dev/null
    grep '^RootHashSignature=/etc/machine-id$' "$fragment" >/dev/null

    # Relative WorkingDirectory path is rejected
    defer_transient_cleanup varlink-transient-bad-wd.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-wd.service","Exec":{"WorkingDirectory":{"path":"relative/path","missingOK":false}},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.WorkingDirectory.path"
    # Malformed environment entry (not KEY=VALUE)
    defer_transient_cleanup varlink-transient-bad-env.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-env.service","Exec":{"Environment":["not_an_env_var"]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.Environment"
    # Invalid User= name is rejected at JSON dispatch time as a parameter error
    defer_transient_cleanup varlink-transient-bad-user.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-user.service","Exec":{"User":"bad/user"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.User"
    # Invalid PAMName= (not a valid file name) is rejected at JSON dispatch time too
    defer_transient_cleanup varlink-transient-bad-pam.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-pam.service","Exec":{"PAMName":"bad/pam"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.PAMName"
    # Out-of-range Nice= value is rejected
    defer_transient_cleanup varlink-transient-bad-nice.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-nice.service","Exec":{"Nice":100},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.Nice"
    # Out-of-range OOMScoreAdjust= value is rejected
    defer_transient_cleanup varlink-transient-bad-oom.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-oom.service","Exec":{"OOMScoreAdjust":9999},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.OOMScoreAdjust"
    # Relative RootDirectory path is rejected
    defer_transient_cleanup varlink-transient-bad-rd.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-rd.service","Exec":{"RootDirectory":"relative/path"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.RootDirectory"
    # Note that an unparsable enum value (e.g. StandardOutput=bogus) is rejected by the Varlink IDL
    # validation layer before the JSON dispatch even runs, hence there's no point in testing pid1's
    # dispatch-level enum handling here — and doing so would trip post.sh's "didn't pass validation"
    # journal check, since the IDL layer logs about the rejection.
    # Relative TTYPath is rejected
    defer_transient_cleanup varlink-transient-bad-ttypath.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-ttypath.service","Exec":{"TTYPath":"relative/tty"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.TTYPath"

    # The file based stdio types need a companion path, and StandardInput=data a companion payload, neither of
    # which can be passed yet, hence they are rejected
    for t in file append truncate; do
        defer_transient_cleanup "varlink-transient-bad-stdout-$t.service"
        expect_invalid_parameter \
            "{\"context\":{\"ID\":\"varlink-transient-bad-stdout-$t.service\",\"Exec\":{\"StandardOutput\":\"$t\"},\"Service\":{\"Type\":\"oneshot\",\"ExecStart\":[{\"path\":\"/bin/true\"}]}}}" \
            "context.Exec.StandardOutput"
    done
    defer_transient_cleanup varlink-transient-bad-stderr.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-stderr.service","Exec":{"StandardError":"file"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.StandardError"
    for t in file data; do
        defer_transient_cleanup "varlink-transient-bad-stdin-$t.service"
        expect_invalid_parameter \
            "{\"context\":{\"ID\":\"varlink-transient-bad-stdin-$t.service\",\"Exec\":{\"StandardInput\":\"$t\"},\"Service\":{\"Type\":\"oneshot\",\"ExecStart\":[{\"path\":\"/bin/true\"}]}}}" \
            "context.Exec.StandardInput"
    done

    # Unknown field in Exec is rejected as PropertyNotSupported
    defer_transient_cleanup varlink-transient-unknown-exec.service
    unsupported_exec=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-unknown-exec.service","Exec":{"AmbientCapabilities":["cap_net_raw"]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' 2>&1 || true)
    echo "$unsupported_exec" | grep "io.systemd.Unit.PropertyNotSupported"
    echo "$unsupported_exec" | grep -F "context.Exec.AmbientCapabilities"
}

testcase_exec_sandbox() {
    setup

    # Exec sandbox scalars: enum and yes/no-string properties round-trip into the reply
    # context (Varlink spelling), systemctl show and the transient fragment (unit-file
    # spelling, so the next daemon-reload keeps the setting)
    defer_transient_cleanup varlink-transient-sandbox.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-sandbox.service","Exec":{"ProtectSystem":"strict","ProtectHome":"read_only","PrivateTmp":"disconnected","PrivateNetwork":"yes","PrivateUsers":"self"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Exec.PrivateTmp == "disconnected"'
    echo "$result" | jq -e '.context.Exec.PrivateNetwork == "yes"'
    echo "$result" | jq -e '.context.Exec.PrivateUsers == "self"'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-sandbox.service; do sleep 0.5; done'
    systemctl show -P PrivateTmpEx varlink-transient-sandbox.service | grep '^disconnected$' >/dev/null
    systemctl show -P PrivateNetwork varlink-transient-sandbox.service | grep '^yes$' >/dev/null
    systemctl show -P PrivateUsersEx varlink-transient-sandbox.service | grep '^self$' >/dev/null
    fragment=$(systemctl show -P FragmentPath varlink-transient-sandbox.service)
    test -n "$fragment"
    grep '^ProtectSystem=strict$'    "$fragment" >/dev/null
    grep '^ProtectHome=read-only$'   "$fragment" >/dev/null
    grep '^PrivateTmp=disconnected$' "$fragment" >/dev/null
    grep '^PrivateNetwork=yes$'      "$fragment" >/dev/null
    grep '^PrivateUsers=self$'       "$fragment" >/dev/null

    # In coverage builds a service.d drop-in sets ProtectSystem=no and ProtectHome=no for all
    # services so gcov can write its *.gcda files. It overrides the transient settings, so the
    # effective values can't be checked there.
    if [[ -n "${COVERAGE_BUILD_DIR:-}" ]]; then
        return 0
    fi

    echo "$result" | jq -e '.context.Exec.ProtectSystem == "strict"'
    echo "$result" | jq -e '.context.Exec.ProtectHome == "read_only"'
    systemctl show -P ProtectSystem varlink-transient-sandbox.service | grep '^strict$' >/dev/null
    systemctl show -P ProtectHome varlink-transient-sandbox.service | grep '^read-only$' >/dev/null

    # The sandbox is live, not just recorded: the unit only succeeds if /usr is read-only
    # and its network namespace differs from PID 1's. Both readlinks are captured first, so
    # an unreadable link fails the unit rather than passing it. Comparing namespaces beats
    # listing interfaces here: the harness runs with --runtime-network=none, and the netns
    # fallback devices come and go with the loaded modules.
    defer_transient_cleanup varlink-transient-sandbox-live.service
    # shellcheck disable=SC2016
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-sandbox-live.service","Exec":{"ProtectSystem":"strict","PrivateNetwork":"yes"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/sh","arguments":["/bin/sh","-c","p=$(readlink /proc/1/ns/net) && s=$(readlink /proc/self/ns/net) && test \"$s\" != \"$p\" && ! touch /usr/varlink-sandbox-canary"]}]}}}' >/dev/null
    timeout 30 bash -c 'until systemctl show -P ActiveState varlink-transient-sandbox-live.service | grep -Ex "active|failed" >/dev/null; do sleep 0.5; done'
    systemctl show -P Result varlink-transient-sandbox-live.service | grep '^success$' >/dev/null
    test ! -e /usr/varlink-sandbox-canary
}

testcase_kill_properties() {
    setup

    # Kill.KillMode/Kill.SendSIGHUP
    defer_transient_cleanup varlink-transient-kill.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-kill.service","Kill":{"KillMode":"process","SendSIGHUP":true},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.Kill.KillMode == "process"'
    echo "$result" | jq -e '.context.Kill.SendSIGHUP == true'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-kill.service; do sleep 0.5; done'
    systemctl show -P KillMode varlink-transient-kill.service | grep '^process$' >/dev/null
    systemctl show -P SendSIGHUP varlink-transient-kill.service | grep '^yes$' >/dev/null

    # Same for a Kill field
    defer_transient_cleanup varlink-transient-unknown-kill.service
    unsupported_kill=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-unknown-kill.service","Kill":{"KillSignal":"SIGINT"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' 2>&1 || true)
    echo "$unsupported_kill" | grep "io.systemd.Unit.PropertyNotSupported"
    echo "$unsupported_kill" | grep -F "context.Kill.KillSignal"
}

testcase_exec_commands() {
    setup

    local payload fragment
    TEMP_FILES+=(/tmp/varlink-exec-{condition,start-pre,start,start-post,reload,reload-post,stop,stop-post})
    rm -f "${TEMP_FILES[@]}"
    defer_transient_cleanup varlink-transient-exec-commands.service

    payload='{"context":{"ID":"varlink-transient-exec-commands.service","Service":{"Type":"oneshot","RemainAfterExit":true,
        "ExecCondition":  [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-condition"]}],
        "ExecStartPre":   [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-start-pre"]}],
        "ExecStart":      [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-start"]}],
        "ExecStartPost":  [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-start-post"]}],
        "ExecReload":     [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-reload"]}],
        "ExecReloadPost": [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-reload-post"]}],
        "ExecStop":       [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-stop"]}],
        "ExecStopPost":   [{"path":"/usr/bin/touch","arguments":["/usr/bin/touch","/tmp/varlink-exec-stop-post"]}]
    }},"notifyJobChanges":true}'

    varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient "$payload" >/dev/null

    fragment=$(systemctl show -P FragmentPath varlink-transient-exec-commands.service)
    grep -Fx 'ExecCondition="/usr/bin/touch" "/tmp/varlink-exec-condition"'          "$fragment" >/dev/null
    grep -Fx 'ExecStartPre="/usr/bin/touch" "/tmp/varlink-exec-start-pre"'           "$fragment" >/dev/null
    grep -Fx 'ExecStart="/usr/bin/touch" "/tmp/varlink-exec-start"'                  "$fragment" >/dev/null
    grep -Fx 'ExecStartPost="/usr/bin/touch" "/tmp/varlink-exec-start-post"'         "$fragment" >/dev/null
    grep -Fx 'ExecReload="/usr/bin/touch" "/tmp/varlink-exec-reload"'                "$fragment" >/dev/null
    grep -Fx 'ExecReloadPost="/usr/bin/touch" "/tmp/varlink-exec-reload-post"'       "$fragment" >/dev/null
    grep -Fx 'ExecStop="/usr/bin/touch" "/tmp/varlink-exec-stop"'                    "$fragment" >/dev/null
    grep -Fx 'ExecStopPost="/usr/bin/touch" "/tmp/varlink-exec-stop-post"'           "$fragment" >/dev/null

    test -e /tmp/varlink-exec-condition
    test -e /tmp/varlink-exec-start-pre
    test -e /tmp/varlink-exec-start
    test -e /tmp/varlink-exec-start-post

    test ! -e /tmp/varlink-exec-reload
    test ! -e /tmp/varlink-exec-reload-post
    systemctl reload varlink-transient-exec-commands.service
    test -e /tmp/varlink-exec-reload
    test -e /tmp/varlink-exec-reload-post

    test ! -e /tmp/varlink-exec-stop
    test ! -e /tmp/varlink-exec-stop-post
    systemctl stop varlink-transient-exec-commands.service
    test -e /tmp/varlink-exec-stop
    test -e /tmp/varlink-exec-stop-post
}

testcase_exec_commands_invalid() {
    setup

    local field unit
    local -a fields=(ExecCondition ExecStartPre ExecStart ExecStartPost ExecReload ExecReloadPost ExecStop ExecStopPost)

    for field in "${fields[@]}"; do
        unit="varlink-transient-invalid-${field}.service"
        defer_transient_cleanup "$unit"
        expect_invalid_parameter \
            '{"context":{"ID":"'"$unit"'","Service":{"Type":"oneshot","'"$field"'":[{"path":"relative/path"}]}}}' \
            "context.Service.$field.path"

        unit="varlink-transient-invalid-flags-${field}.service"
        defer_transient_cleanup "$unit"
        expect_invalid_parameter \
            '{"context":{"ID":"'"$unit"'","Service":{"Type":"oneshot","'"$field"'":[{"path":"/bin/true","privileged":true,"noSetuid":true}]}}}' \
            "context.Service.$field"
    done
}

testcase_exec_flags() {
    setup

    # shellcheck disable=SC2016
    TEMP_FILES+=(/tmp/varlink-transient-execflags-expanded '/tmp/varlink-transient-execflags-${FLAGTEST}'
                  /tmp/varlink-transient-execflags-shell /run/varlink-transient-execflags-{plain,privileged,nosetuid})

    # ExecStart execution flags, i.e. the Varlink counterparts of the "-", ":", "|", "+" and "!" prefixes of
    # unit file ExecStart= lines. First the ones observable from an unprivileged unit:
    #  - ignoreFailure: a failing command does not fail the unit
    #  - noEnvExpand: "${VAR}" in the arguments is passed as-is rather than expanded
    #  - viaShell: the command line is handed to the user's shell via "-c" (argv[0] is normalized to "sh")
    rm -f /tmp/varlink-transient-execflags-*
    defer_transient_cleanup varlink-transient-execflags.service
    # shellcheck disable=SC2016
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-execflags.service","Exec":{"Environment":["FLAGTEST=expanded"]},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[
            {"path":"/bin/false","ignoreFailure":true},
            {"path":"/usr/bin/touch","arguments":["touch","/tmp/varlink-transient-execflags-${FLAGTEST}"]},
            {"path":"/usr/bin/touch","arguments":["touch","/tmp/varlink-transient-execflags-${FLAGTEST}"],"noEnvExpand":true},
            {"path":"/bin/sh","arguments":["sh","touch","/tmp/varlink-transient-execflags-shell"],"viaShell":true}]}}}')
    echo "$result" | jq -e '.context.Service.ExecStart[0].ignoreFailure == true'
    echo "$result" | jq -e '.context.Service.ExecStart[1].noEnvExpand == false'
    echo "$result" | jq -e '.context.Service.ExecStart[2].noEnvExpand == true'
    echo "$result" | jq -e '.context.Service.ExecStart[3].viaShell == true'
    echo "$result" | jq -e '.context.Service.ExecStart[3].path == "/bin/sh"'
    echo "$result" | jq -e '.context.Service.ExecStart[3].arguments[0] == "sh"'
    # The unit only becomes active once all ExecStart= commands succeeded (or were allowed to fail)
    timeout 30 bash -c 'until systemctl is-active varlink-transient-execflags.service; do sleep 0.5; done'
    test -e /tmp/varlink-transient-execflags-expanded
    # shellcheck disable=SC2016
    test -e '/tmp/varlink-transient-execflags-${FLAGTEST}'
    test -e /tmp/varlink-transient-execflags-shell
    # The flags must show up as the matching prefix characters in the transient unit file
    fragment=$(systemctl show -P FragmentPath varlink-transient-execflags.service)
    grep -E '^ExecStart=-"/bin/false"$' "$fragment" >/dev/null
    grep -E '^ExecStart=:' "$fragment" >/dev/null
    grep -E '^ExecStart=\|' "$fragment" >/dev/null
    rm -f /tmp/varlink-transient-execflags-*

    # Now the privilege related ones, in a unit running as an unprivileged user:
    #  - privileged/noSetuid: the command runs with full privileges, i.e. can write where the user cannot
    #  - (neither): the command runs as the user, and fails to write there (tolerated via ignoreFailure)
    rm -f /run/varlink-transient-execflags-*
    defer_transient_cleanup varlink-transient-execflags-priv.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-execflags-priv.service","Exec":{"User":"nobody"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[
            {"path":"/usr/bin/touch","arguments":["touch","/run/varlink-transient-execflags-plain"],"ignoreFailure":true},
            {"path":"/usr/bin/touch","arguments":["touch","/run/varlink-transient-execflags-privileged"],"privileged":true},
            {"path":"/usr/bin/touch","arguments":["touch","/run/varlink-transient-execflags-nosetuid"],"noSetuid":true}]}}}')
    echo "$result" | jq -e '.context.Service.ExecStart[0].privileged == false'
    echo "$result" | jq -e '.context.Service.ExecStart[1].privileged == true'
    echo "$result" | jq -e '.context.Service.ExecStart[2].noSetuid == true'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-execflags-priv.service; do sleep 0.5; done'
    test ! -e /run/varlink-transient-execflags-plain
    test -e /run/varlink-transient-execflags-privileged
    test -e /run/varlink-transient-execflags-nosetuid
    fragment=$(systemctl show -P FragmentPath varlink-transient-execflags-priv.service)
    grep -E '^ExecStart=\+' "$fragment" >/dev/null
    grep -E '^ExecStart=!' "$fragment" >/dev/null
    rm -f /run/varlink-transient-execflags-*

    # The 'privileged' and 'noSetuid' execution flags are mutually exclusive
    defer_transient_cleanup varlink-transient-badflags.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-badflags.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true","privileged":true,"noSetuid":true}]}}}' \
        "context.Service.ExecStart"
}

testcase_credentials() {
    setup

    # Exec.SetCredential: pass a credential and verify the running process can read it
    defer_transient_cleanup varlink-transient-cred.service
    CRED_VALUE_B64=$(printf 'secret-value' | base64 -w0)
    CRED_OUTPUT=$(mktemp)
    TEMP_FILES+=("$CRED_OUTPUT")
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        "{\"context\":{\"ID\":\"varlink-transient-cred.service\",\"Exec\":{\"SetCredential\":[{\"id\":\"mycred\",\"value\":\"${CRED_VALUE_B64}\"}]},\"Service\":{\"Type\":\"oneshot\",\"RemainAfterExit\":true,\"ExecStart\":[{\"path\":\"/bin/sh\",\"arguments\":[\"/bin/sh\",\"-c\",\"cat \$CREDENTIALS_DIRECTORY/mycred > ${CRED_OUTPUT}\"]}]}}}"
    timeout 30 bash -c "until systemctl is-active varlink-transient-cred.service; do sleep 0.5; done"
    grep '^secret-value$' "$CRED_OUTPUT" >/dev/null
    rm -f "$CRED_OUTPUT"

    # Invalid credential ID
    defer_transient_cleanup varlink-transient-bad-cred-id.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-cred-id.service","Exec":{"SetCredential":[{"id":"bad/id","value":"YWJj"}]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.SetCredential.id"
    # Invalid base64 value for credential (rejected at JSON dispatch time as a parameter error)
    defer_transient_cleanup varlink-transient-bad-cred-value.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-cred-value.service","Exec":{"SetCredential":[{"id":"mycred","value":"!!!not_base64!!!"}]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.Exec.SetCredential.value"
}

testcase_file_descriptors() {
    setup

    local field

    defer_transient_cleanup varlink-transient-missing-fd.service
    for field in StandardInputFileDescriptor StandardOutputFileDescriptor StandardErrorFileDescriptor; do
        expect_invalid_parameter \
            '{"context":{"ID":"varlink-transient-missing-fd.service","Service":{"'"$field"'":0}}}' \
            "context.Service.$field"
    done

    # Service.Standard{Output,Error}FileDescriptor: connect passed fds (by push order)
    # to the unit's stdout/stderr; regular files, so output can be checked after exit.
    transient_out=$(mktemp)
    TEMP_FILES+=("$transient_out")
    transient_err=$(mktemp)
    TEMP_FILES+=("$transient_err")
    exec {transient_out_fd}>"$transient_out"
    exec {transient_err_fd}>"$transient_err"
    defer_transient_cleanup varlink-transient-fdpass.service
    varlinkctl --push-fd="$transient_out_fd" --push-fd="$transient_err_fd" \
        call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-fdpass.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/sh","arguments":["/bin/sh","-c","echo to-stdout; echo to-stderr >&2"]}],"StandardOutputFileDescriptor":0,"StandardErrorFileDescriptor":1}}}' >/dev/null
    # Close our copies so the unit holds the only remaining write ends.
    exec {transient_out_fd}>&-
    exec {transient_err_fd}>&-
    timeout 30 bash -c 'until systemctl show -P ActiveState varlink-transient-fdpass.service | grep inactive >/dev/null; do sleep 0.5; done'
    systemctl show -P Result varlink-transient-fdpass.service | grep success >/dev/null
    grep -x to-stdout "$transient_out" >/dev/null
    grep -x to-stderr "$transient_err" >/dev/null
    rm -f "$transient_out" "$transient_err"
}

testcase_scope() {
    setup

    # Starting a transient scope
    defer_transient_cleanup varlink-transient-scope.scope
    sleep infinity &
    scope_child="$!"
    CHILD_PIDS+=("$scope_child")
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        "{\"context\":{\"ID\":\"varlink-transient-scope.scope\",\"Scope\":{\"PIDs\":[{\"pid\":${scope_child}}],\"OOMPolicy\":\"kill\", \"TimeoutStopUSec\":12000000}}}"
    timeout 30 bash -c 'until systemctl is-active varlink-transient-scope.scope; do sleep 0.5; done'
    systemctl whoami "$scope_child" | grep "^varlink-transient-scope.scope$" >/dev/null
    systemctl show -P TimeoutStopUSec varlink-transient-scope.scope | grep 12s >/dev/null
    systemctl show -P OOMPolicy varlink-transient-scope.scope | grep kill >/dev/null

    # Bad PID on a scope
    defer_transient_cleanup varlink-transient-badpid.scope
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-badpid.scope","Scope":{"PIDs":[{"pid": 1}]}}}' \
        "context.Scope.PIDs"
}

testcase_dependencies() {
    setup

    defer_transient_cleanup varlink-transient-dependency.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-dependency.service","Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-dependency.service; do sleep 0.5; done'

    # Unit dependencies
    defer_transient_cleanup varlink-transient-deps.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-deps.service","After":["varlink-transient-dependency.service"],"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-deps.service; do sleep 0.5; done'
    systemctl show -P After varlink-transient-deps.service | grep varlink-transient-dependency.service >/dev/null

    # Dependency on invalid unit (rejected at dispatch time)
    defer_transient_cleanup varlink-invalid-dependency.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-invalid-dependency.service","Requires":["invalid@.service"],"Service":{"ExecStart":[{"path":"/usr/bin/true"}]}}}' \
        "context.Requires"

    # The name passes dispatch validation, but slice units cannot be instantiated.
    defer_transient_cleanup varlink-invalid-dependency-instance.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-invalid-dependency-instance.service","Requires":["varlink-dependency@invalid.slice"],"Service":{"ExecStart":[{"path":"/usr/bin/true"}]}}}' \
        "context.Requires"

    # Non-transient dependency types are rejected as PropertyNotSupported
    defer_transient_cleanup varlink-non-transient-dependency.service
    non_transient_dep=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-non-transient-dependency.service","Triggers":["varlink-transient-dependency.service"],"Service":{"ExecStart":[{"path":"/usr/bin/true"}]}}}' 2>&1 || true)
    echo "$non_transient_dep" | grep "io.systemd.Unit.PropertyNotSupported"
    echo "$non_transient_dep" | grep -F "context.Triggers"
}

testcase_cgroup() {
    setup

    # CGroup context: scalar resource-control properties round-trip into the reply
    # context, systemctl show and the transient fragment
    defer_transient_cleanup varlink-transient-cgroup.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup.service","CGroup":{"CPUWeight":200,"StartupCPUWeight":150,"CPUQuotaPerSecUSec":500000,"CPUQuotaPeriodUSec":20000,"MemoryAccounting":true,"MemoryLow":8388608,"StartupMemoryLow":4194304,"MemoryHigh":33554432,"MemoryMax":67108864,"TasksAccounting":true,"TasksMax":{"value":16},"IOAccounting":true,"IOWeight":100},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.CPUWeight == 200'
    echo "$result" | jq -e '.context.CGroup.StartupCPUWeight == 150'
    echo "$result" | jq -e '.context.CGroup.CPUQuotaPerSecUSec == 500000'
    echo "$result" | jq -e '.context.CGroup.CPUQuotaPeriodUSec == 20000'
    echo "$result" | jq -e '.context.CGroup.StartupMemoryLow == 4194304'
    echo "$result" | jq -e '.context.CGroup.MemoryMax == 67108864'
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":16,"scale":0}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-cgroup.service; do sleep 0.5; done'
    systemctl show -P CPUWeight varlink-transient-cgroup.service | grep -Fx 200 >/dev/null
    systemctl show -P CPUQuotaPerSecUSec varlink-transient-cgroup.service | grep -Fx 500ms >/dev/null
    systemctl show -P CPUQuotaPeriodUSec varlink-transient-cgroup.service | grep -Fx 20ms >/dev/null
    systemctl show -P MemoryLow varlink-transient-cgroup.service | grep -Fx 8388608 >/dev/null
    systemctl show -P MemoryHigh varlink-transient-cgroup.service | grep -Fx 33554432 >/dev/null
    systemctl show -P MemoryMax varlink-transient-cgroup.service | grep -Fx 67108864 >/dev/null
    systemctl show -P TasksMax varlink-transient-cgroup.service | grep -Fx 16 >/dev/null
    systemctl show -P IOWeight varlink-transient-cgroup.service | grep -Fx 100 >/dev/null
    # The fragment must use the unit-file directive spellings (CPUQuota=, not the JSON
    # property name), otherwise the next daemon-reload would drop the setting.
    fragment=$(systemctl show -P FragmentPath varlink-transient-cgroup.service)
    test -n "$fragment"
    grep -Fx 'CPUQuota=50.00%'        "$fragment" >/dev/null
    grep -Fx 'CPUQuotaPeriodSec=20ms' "$fragment" >/dev/null
    grep -Fx 'MemoryMax=67108864'     "$fragment" >/dev/null
    grep -Fx 'TasksMax=16'            "$fragment" >/dev/null

    # The special values are written as TasksMax=infinity, CPUWeight=idle and an empty
    # StartupCPUWeight= (UINT64_MAX resets a weight to the default)
    defer_transient_cleanup varlink-transient-cgroup-special.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-special.service","CGroup":{"TasksMax":{"value":18446744073709551615},"CPUWeight":0,"StartupCPUWeight":18446744073709551615},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}' >/dev/null
    timeout 30 bash -c 'until systemctl is-active varlink-transient-cgroup-special.service; do sleep 0.5; done'
    systemctl show -P TasksMax varlink-transient-cgroup-special.service | grep -Fx infinity >/dev/null
    fragment=$(systemctl show -P FragmentPath varlink-transient-cgroup-special.service)
    test -n "$fragment"
    grep -Fx 'TasksMax=infinity' "$fragment" >/dev/null
    grep -Fx 'CPUWeight=idle'    "$fragment" >/dev/null
    grep -Fx 'StartupCPUWeight=' "$fragment" >/dev/null

    # Cgroup limits materialize on the live cgroup
    defer_transient_cleanup varlink-transient-cgroup-live.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-live.service","CGroup":{"MemoryMax":67108864,"TasksMax":{"value":16}},"Service":{"ExecStart":[{"path":"/usr/bin/sleep","arguments":["/usr/bin/sleep","infinity"]}]}}}' >/dev/null
    timeout 10 bash -c 'until systemctl is-active varlink-transient-cgroup-live.service; do sleep 0.5; done'
    cgroup_path=$(systemctl show -P ControlGroup varlink-transient-cgroup-live.service)
    test -n "$cgroup_path"
    grep -Fx 67108864 "/sys/fs/cgroup${cgroup_path}/memory.max" >/dev/null
    grep -Fx 16       "/sys/fs/cgroup${cgroup_path}/pids.max" >/dev/null

    # Slice= places the unit under an implicitly created slice
    defer_transient_cleanup varlink-transient-slice.service
    defer_transient_cleanup varlink-test.slice
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-slice.service","CGroup":{"Slice":"varlink-test.slice"},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.Slice == "varlink-test.slice"'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-slice.service; do sleep 0.5; done'
    systemctl show -P Slice varlink-transient-slice.service | grep -Fx varlink-test.slice >/dev/null

    # Relative forms: TasksMaxScale/MemoryMaxScale (floats, 1.0 == 100%) are input only,
    # converted internally and written to the fragment as permyriad percentages. An
    # explicit null is treated as absent (so MemoryMax=null does not conflict with
    # MemoryMaxScale), and a zero scale is accepted for the min-0 memory properties,
    # as over D-Bus
    defer_transient_cleanup varlink-transient-cgroup-scale.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-scale.service","CGroup":{"TasksMaxScale":0.5,"MemoryMax":null,"MemoryMaxScale":0.125,"MemoryMinScale":0.0,"TasksAccounting":null},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":5000,"scale":10000}'
    echo "$result" | jq -e '.context.CGroup.TasksMaxScale == null'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-cgroup-scale.service; do sleep 0.5; done'
    fragment=$(systemctl show -P FragmentPath varlink-transient-cgroup-scale.service)
    test -n "$fragment"
    grep -Fx 'TasksMax=50.00%'  "$fragment" >/dev/null
    grep -Fx 'MemoryMax=12.50%' "$fragment" >/dev/null
    grep -Fx 'MemoryMin=0.00%'  "$fragment" >/dev/null
    (! grep -F 'TasksAccounting=' "$fragment")

    # A null scale member of TasksMax is absent, not a request for the relative form
    defer_transient_cleanup varlink-transient-cgroup-nullscale.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-nullscale.service","CGroup":{"TasksMax":{"value":16,"scale":null}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":16,"scale":0}'

    # Out-of-range CPUWeight= is rejected
    defer_transient_cleanup varlink-transient-bad-weight.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-weight.service","CGroup":{"CPUWeight":123456},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.CPUWeight"
    # IOWeight=0 is rejected, only the CPU weights accept idle
    defer_transient_cleanup varlink-transient-bad-ioweight.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-ioweight.service","CGroup":{"IOWeight":0},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.IOWeight"
    # MemoryMax=0 is rejected (minimum 1, matching the D-Bus setter)
    defer_transient_cleanup varlink-transient-bad-memmax.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-memmax.service","CGroup":{"MemoryMax":0},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.MemoryMax"
    # A scaled TasksMax above 100% is rejected
    defer_transient_cleanup varlink-transient-bad-taskspair.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-taskspair.service","CGroup":{"TasksMax":{"value":2,"scale":1}},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.TasksMax"
    # So is a denominator past UINT32_MAX: system_tasks_max_scale() would overflow and resolve
    # to no limit at all, while the fragment still recorded a percentage
    defer_transient_cleanup varlink-transient-bad-tasksdenom.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-tasksdenom.service","CGroup":{"TasksMax":{"value":5000000000000,"scale":10000000000000}},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.TasksMax"
    # Out-of-range TasksMaxScale= (>= 100%) is rejected
    defer_transient_cleanup varlink-transient-bad-tasksscale.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-tasksscale.service","CGroup":{"TasksMaxScale":1.5},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.TasksMaxScale"
    # Absolute and relative forms of the same limit may not be combined
    defer_transient_cleanup varlink-transient-bad-taskscombo.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-taskscombo.service","CGroup":{"TasksMax":{"value":16},"TasksMaxScale":0.5},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.TasksMaxScale"
    # Zero MemoryMaxScale= is rejected
    defer_transient_cleanup varlink-transient-bad-memscale.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-memscale.service","CGroup":{"MemoryMaxScale":0.0},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.MemoryMaxScale"
    # Slice= pointing at a non-slice unit is rejected
    defer_transient_cleanup varlink-transient-bad-slice.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-slice.service","CGroup":{"Slice":"not-a-slice.service"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
        "context.CGroup.Slice"
    # CGroup field declared in the IDL but not yet settable at creation is rejected as
    # PropertyNotSupported, and the offending sub-property is identified
    defer_transient_cleanup varlink-transient-unknown-cgroup.service
    unsupported_cgroup=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-unknown-cgroup.service","CGroup":{"DeviceAllow":[]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' 2>&1 || true)
    echo "$unsupported_cgroup" | grep "io.systemd.Unit.PropertyNotSupported"
    echo "$unsupported_cgroup" | grep -F "context.CGroup.DeviceAllow"
}

testcase_cgroup_tasks_max_pair() {
    setup

    # An absolute limit is emitted as {"value":N,"scale":0}, which is the common read-side
    # shape; feeding it back has to keep it absolute rather than reading scale as a denominator
    defer_transient_cleanup varlink-transient-cgroup-abspair.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-abspair.service","CGroup":{"TasksMax":{"value":16,"scale":0}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":16,"scale":0}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-cgroup-abspair.service; do sleep 0.5; done'
    systemctl show -P TasksMax varlink-transient-cgroup-abspair.service | grep -Fx 16 >/dev/null
    fragment=$(systemctl show -P FragmentPath varlink-transient-cgroup-abspair.service)
    test -n "$fragment"
    grep -Fx 'TasksMax=16' "$fragment" >/dev/null

    # The TasksMax pair is taken exactly as the read side emits it, so a reply can be fed
    # straight back into StartTransient. The fragment carries the normalized permyriad percent.
    defer_transient_cleanup varlink-transient-cgroup-pair.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-pair.service","CGroup":{"TasksMax":{"value":5000,"scale":10000}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":5000,"scale":10000}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-cgroup-pair.service; do sleep 0.5; done'
    fragment=$(systemctl show -P FragmentPath varlink-transient-cgroup-pair.service)
    test -n "$fragment"
    grep -Fx 'TasksMax=50.00%' "$fragment" >/dev/null

    tasks_max=$(echo "$result" | jq -c '.context.CGroup.TasksMax')
    defer_transient_cleanup varlink-transient-cgroup-roundtrip.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        "{\"context\":{\"ID\":\"varlink-transient-cgroup-roundtrip.service\",\"CGroup\":{\"TasksMax\":$tasks_max},\"Service\":{\"Type\":\"oneshot\",\"RemainAfterExit\":true,\"ExecStart\":[{\"path\":\"/bin/true\"}]}}}")
    echo "$result" | jq -e --argjson t "$tasks_max" '.context.CGroup.TasksMax == $t'

    # The denominator is whatever configured the unit, so the one the D-Bus TasksMaxScale
    # setter uses (UINT32_MAX) has to be accepted too, not just the permyriad one
    defer_transient_cleanup varlink-transient-cgroup-dbusscale.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-dbusscale.service","CGroup":{"TasksMax":{"value":2147483647,"scale":4294967295}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":2147483647,"scale":4294967295}'
    timeout 30 bash -c 'until systemctl is-active varlink-transient-cgroup-dbusscale.service; do sleep 0.5; done'
    fragment=$(systemctl show -P FragmentPath varlink-transient-cgroup-dbusscale.service)
    grep -Fx 'TasksMax=50.00%' "$fragment" >/dev/null

    # TasksMaxScale refuses 0% and 100%, but the unit-file parser accepts both, so they reach
    # the read side and the pair form has to take them back. Only the reply is asserted: a 0%
    # limit leaves the unit unable to fork.
    defer_transient_cleanup varlink-transient-cgroup-zeroscale.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-zeroscale.service","CGroup":{"TasksMax":{"value":0,"scale":10000}},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":0,"scale":10000}'
    defer_transient_cleanup varlink-transient-cgroup-fullscale.service
    result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-cgroup-fullscale.service","CGroup":{"TasksMax":{"value":10000,"scale":10000}},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
    echo "$result" | jq -e '.context.CGroup.TasksMax == {"value":10000,"scale":10000}'
}

testcase_dispatch_error_paths() {
    setup

    local field

    expect_invalid_parameter \
        '{"context":{"ID":"bad/unit.service"}}' \
        "context.ID"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-null-exec.service","Exec":null}}' \
        "context.Exec"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-null-wd.service","Exec":{"WorkingDirectory":null}}}' \
        "context.Exec.WorkingDirectory"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-null-wd-path.service","Exec":{"WorkingDirectory":{"path":null}}}}' \
        "context.Exec.WorkingDirectory.path"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-wd-bad-user.service","Exec":{"WorkingDirectory":{"path":"/tmp"},"User":"bad/user"}}}' \
        "context.Exec.User"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-dependency.service","Exec":{"User":"root"},"Requires":["bad/unit.service"]}}' \
        "context.Requires"

    for field in SetCredential SetCredentialEncrypted; do
        expect_invalid_parameter \
            '{"context":{"ID":"varlink-transient-bad-credential-array.service","Exec":{"'"$field"'":[{"id":"first","value":"YWJj"},{"id":"second","value":"!!!not_base64!!!"}]}}}' \
            "context.Exec.$field.value"
    done

    for field in ExecCondition ExecStartPre ExecStart ExecStartPost ExecReload ExecReloadPost ExecStop ExecStopPost; do
        expect_invalid_parameter \
            '{"context":{"ID":"varlink-transient-bad-command-array.service","Service":{"'"$field"'":[{"path":"/bin/true"},{"path":"/bin/true","arguments":["/bin/true"],"ignoreFailure":null}]}}}' \
            "context.Service.$field.ignoreFailure"
    done

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-tasks-value.service","CGroup":{"TasksMax":{"value":-1}}}}' \
        "context.CGroup.TasksMax.value"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-bad-tasks-scale.service","CGroup":{"TasksMax":{"value":1,"scale":-1}}}}' \
        "context.CGroup.TasksMax.scale"

    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-tasks-bad-weight.service","CGroup":{"TasksMax":{"value":16},"CPUWeight":-1}}}' \
        "context.CGroup.CPUWeight"
}

testcase_exec_apply_error_paths() {
    setup

    local field unit

    for field in SetCredential SetCredentialEncrypted; do
        unit="varlink-transient-invalid-${field}.service"
        defer_transient_cleanup "$unit"
        expect_invalid_parameter \
            '{"context":{"ID":"'"$unit"'","Exec":{"'"$field"'":[{"id":"first","value":"YWJj"},{"id":"bad/id","value":"YWJj"}]}}}' \
            "context.Exec.$field.id"
    done

    defer_transient_cleanup varlink-transient-wd-bad-nice.service
    expect_invalid_parameter \
        '{"context":{"ID":"varlink-transient-wd-bad-nice.service","Exec":{"WorkingDirectory":{"path":"/tmp"},"Nice":100}}}' \
        "context.Exec.Nice"
}

testcase_validation() {
    setup

    # Creating an already active unit must fail.
    defer_transient_cleanup varlink-transient-exists.service
    varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
        '{"context":{"ID":"varlink-transient-exists.service","Service":{"ExecStart":[{"path":"/usr/bin/sleep","arguments":["/usr/bin/sleep","infinity"]}]}}}'
    timeout 10 bash -c 'until systemctl is-active varlink-transient-exists.service; do sleep 0.5; done'

    # Error cases: verify specific varlink error types
    (
        set +o pipefail
        varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
            '{"context":{"ID":"varlink-transient-exists.service","Service":{"ExecStart":[{"path":"/usr/bin/sleep","arguments":["/usr/bin/sleep","infinity"]}]}}}' |& grep "io.systemd.Unit.UnitExists"
    )
    (
        set +o pipefail
        varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
            '{"context":{"ID":"varlink-transient-test.target","Description":"test"}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
    )

    # Exec on a unit type without an exec context (.slice) is rejected
    (
        set +o pipefail
        varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
            '{"context":{"ID":"varlink-transient-exec.slice","Exec":{"WorkingDirectory":{"path":"/tmp","missingOK":false}}}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
    )
    # Same for Kill on a unit type without a kill context
    (
        set +o pipefail
        varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
            '{"context":{"ID":"varlink-transient-kill.slice","Kill":{"KillMode":"process"}}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
    )
}

run_testcases
