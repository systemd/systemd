#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# test io.systemd.Unit
varlinkctl info /run/systemd/io.systemd.Manager
varlinkctl introspect /run/systemd/io.systemd.Manager io.systemd.Unit
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "multi-user.target"}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": 1}}'
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' |& grep "called without 'more' flag" >/dev/null)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "init.scope", "pid": {"pid": 1}}'
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": ""}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "non-existent.service"}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": -1}}' )
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "multi-user.target", "pid": {"pid": 1}}')
set +o pipefail
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties '{"runtime": true, "name": "non-existent.service", "properties": {"Markers": ["needs-restart"]}}' |& grep "io.systemd.Unit.NoSuchUnit"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties '{"runtime": true, "name": "systemd-journald.service", "properties": {"LoadState": "foobar"}}' |& grep "io.systemd.Unit.PropertyNotSupported"
set -o pipefail

varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"cgroup": "/init.scope"}'
invocation_id="$(systemctl show -P InvocationID systemd-journald.service)"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "{\"invocationID\": \"$invocation_id\"}"
# test for KillContext
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": 0}}' | jq -e '.context.Kill'
# test for AutomountContext/Runtime
automount_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "automount" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$automount_id"
# Use jq to JSON-encode the unit name as it may contain backslash escapes (e.g. \x2d) that
# are not valid JSON escape sequences and would be rejected by varlinkctl's JSON parser.
automount_params=$(jq -cn --arg name "$automount_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$automount_params" | jq -e '.context.Automount'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$automount_params" | jq -e '.runtime.Automount'
# test for MountContext/Runtime (skip volatile run-user-*.mount to avoid GC race)
mount_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "mount" and .runtime.LoadState == "loaded" and (.context.ID | startswith("run-user-") | not)) .context.ID // empty' | tail -n 1)
test -n "$mount_id"
mount_params=$(jq -cn --arg name "$mount_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$mount_params" | jq -e '.context.Mount'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$mount_params" | jq -e '.runtime.Mount'
# test for PathContext/Runtime
path_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "path" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$path_id"
path_params=$(jq -cn --arg name "$path_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$path_params" | jq -e '.context.Path'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$path_params" | jq -e '.runtime.Path'
# test for ServiceContext/Runtime (skip volatile user@*/user-runtime-dir@* to avoid GC race)
service_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "service" and .runtime.LoadState == "loaded" and (.context.ID | test("^(user|user-runtime-dir)@") | not)) .context.ID // empty' | tail -n 1)
test -n "$service_id"
service_params=$(jq -cn --arg name "$service_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$service_params" | jq -e '.context.Service'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$service_params" | jq -e '.runtime.Service'
# test for ScopeContext/Runtime (skip volatile session-*.scope to avoid GC race)
scope_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "scope" and .runtime.LoadState == "loaded" and (.context.ID | startswith("session-") | not)) .context.ID // empty' | tail -n 1)
test -n "$scope_id"
scope_params=$(jq -cn --arg name "$scope_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$scope_params" | jq -e '.context.Scope'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$scope_params" | jq -e '.runtime.Scope'
# test for SocketContext/Runtime
socket_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "socket" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$socket_id"
socket_params=$(jq -cn --arg name "$socket_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$socket_params" | jq -e '.context.Socket'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$socket_params" | jq -e '.runtime.Socket'
# test for SwapContext/Runtime (swap units may not be present on all systems)
swap_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "swap" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
if test -n "$swap_id"; then
    swap_params=$(jq -cn --arg name "$swap_id" '{name: $name}')
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$swap_params" | jq -e '.context.Swap'
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$swap_params" | jq -e '.runtime.Swap'
fi
# test for TimerContext/Runtime
timer_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "timer" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$timer_id"
timer_params=$(jq -cn --arg name "$timer_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$timer_params" | jq -e '.context.Timer'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$timer_params" | jq -e '.runtime.Timer'

# test io.systemd.Unit in user manager
testuser_uid=$(id -u testuser)
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl --more call "/run/user/$testuser_uid/systemd/io.systemd.Manager" io.systemd.Unit.List '{}'

# Test io.systemd.Unit.StartTransient
MANAGER_SOCKET="/run/systemd/io.systemd.Manager"

TRANSIENT_UNITS=()
defer_transient_cleanup() {
    TRANSIENT_UNITS+=("$1")
}
transient_cleanup() {
    for u in "${TRANSIENT_UNITS[@]}"; do
        systemctl stop "$u" 2>/dev/null || true
        systemctl reset-failed "$u" 2>/dev/null || true
    done
}
trap transient_cleanup EXIT

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

# prepare for the error case below: create a long-running service, then try to create it again while it's active
defer_transient_cleanup varlink-transient-exists.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-exists.service","Service":{"ExecStart":[{"path":"/usr/bin/sleep","arguments":["/usr/bin/sleep","infinity"]}]}}}'
timeout 10 bash -c 'until systemctl is-active varlink-transient-exists.service; do sleep 0.5; done'

# Multiple ExecStart commands (oneshot allows multiple)
defer_transient_cleanup varlink-transient-multi.service
result=$(varlinkctl call --more "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-multi.service","Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"},{"path":"/bin/true"}]}},"notifyJobChanges":true}')
printf '%s' "$result" | jq --seq --slurp -e 'any(.[]; .job.Result == "done")' >/dev/null

# Transient service with Description and RemainAfterExit
defer_transient_cleanup varlink-transient-desc.service
result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-desc.service","Description":"Test description property","Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
echo "$result" | jq -e '.context.Description == "Test description property"'
echo "$result" | jq -e '.context.Service.Type == "oneshot"'
echo "$result" | jq -e '.context.Service.RemainAfterExit == true'
echo "$result" | jq -e '.context.Service.ExecStart[0].path == "/bin/true"'
echo "$result" | jq -e '.runtime'

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

# Exec.WorkingDirectory and Exec.Environment
defer_transient_cleanup varlink-transient-exec.service
result=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-exec.service","Exec":{"WorkingDirectory":{"path":"/tmp","missingOK":false},"Environment":["FOO=bar","BAZ=qux"]},"Service":{"Type":"oneshot","RemainAfterExit":true,"ExecStart":[{"path":"/bin/true"}]}}}')
echo "$result" | jq -e '.context.Exec.WorkingDirectory.path == "/tmp"'
echo "$result" | jq -e '.context.Exec.Environment | index("FOO=bar") != null'
echo "$result" | jq -e '.context.Exec.Environment | index("BAZ=qux") != null'
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

# Exec.SetCredential: pass a credential and verify the running process can read it
defer_transient_cleanup varlink-transient-cred.service
CRED_VALUE_B64=$(printf 'secret-value' | base64 -w0)
CRED_OUTPUT=$(mktemp)
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    "{\"context\":{\"ID\":\"varlink-transient-cred.service\",\"Exec\":{\"SetCredential\":[{\"id\":\"mycred\",\"value\":\"${CRED_VALUE_B64}\"}]},\"Service\":{\"Type\":\"oneshot\",\"RemainAfterExit\":true,\"ExecStart\":[{\"path\":\"/bin/sh\",\"arguments\":[\"/bin/sh\",\"-c\",\"cat \$CREDENTIALS_DIRECTORY/mycred > ${CRED_OUTPUT}\"]}]}}}"
timeout 30 bash -c "until systemctl is-active varlink-transient-cred.service; do sleep 0.5; done"
grep '^secret-value$' "$CRED_OUTPUT" >/dev/null
rm -f "$CRED_OUTPUT"

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

# Error cases: verify specific varlink error types
set +o pipefail
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-exists.service","Service":{"ExecStart":[{"path":"/usr/bin/sleep","arguments":["/usr/bin/sleep","infinity"]}]}}}' |& grep "io.systemd.Unit.UnitExists"
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-test.target","Description":"test"}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
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
defer_transient_cleanup varlink-transient-bad.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad.service","Service":{"Type":"simple"}}}' \
    "context"
# Invalid ExecStart path: exercises filename_or_absolute_path_is_valid() in transient_service_apply_properties()
defer_transient_cleanup varlink-transient-badpath.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-badpath.service","Service":{"Type":"simple","ExecStart":[{"path":""}]}}}' \
    "Service.ExecStart"
# Relative WorkingDirectory path is rejected
defer_transient_cleanup varlink-transient-bad-wd.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-wd.service","Exec":{"WorkingDirectory":{"path":"relative/path","missingOK":false}},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "Exec.WorkingDirectory"
# Malformed environment entry (not KEY=VALUE)
defer_transient_cleanup varlink-transient-bad-env.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-env.service","Exec":{"Environment":["not_an_env_var"]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "Exec.Environment"
# Invalid User= name is rejected at JSON dispatch time as a parameter error
defer_transient_cleanup varlink-transient-bad-user.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-user.service","Exec":{"User":"bad/user"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "context"
# Out-of-range Nice= value is rejected
defer_transient_cleanup varlink-transient-bad-nice.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-nice.service","Exec":{"Nice":100},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "Exec.Nice"
# Out-of-range OOMScoreAdjust= value is rejected
defer_transient_cleanup varlink-transient-bad-oom.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-oom.service","Exec":{"OOMScoreAdjust":9999},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "Exec.OOMScoreAdjust"
# Relative RootDirectory path is rejected
defer_transient_cleanup varlink-transient-bad-rd.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-rd.service","Exec":{"RootDirectory":"relative/path"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "Exec.RootDirectory"
# Invalid credential ID
defer_transient_cleanup varlink-transient-bad-cred-id.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-cred-id.service","Exec":{"SetCredential":[{"id":"bad/id","value":"YWJj"}]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "Exec.SetCredential"
# Invalid base64 value for credential (rejected at JSON dispatch time as a parameter error)
defer_transient_cleanup varlink-transient-bad-cred-value.service
expect_invalid_parameter \
    '{"context":{"ID":"varlink-transient-bad-cred-value.service","Exec":{"SetCredential":[{"id":"mycred","value":"!!!not_base64!!!"}]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' \
    "context"
# Exec on a unit type without an exec context (.slice) is rejected
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-exec.slice","Exec":{"WorkingDirectory":{"path":"/tmp","missingOK":false}}}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
# Unknown field in Exec is rejected as PropertyNotSupported
defer_transient_cleanup varlink-transient-unknown-exec.service
unsupported_exec=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-unknown-exec.service","Exec":{"AmbientCapabilities":["cap_net_raw"]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' 2>&1 || true)
echo "$unsupported_exec" | grep "io.systemd.Unit.PropertyNotSupported"
echo "$unsupported_exec" | grep "Exec.AmbientCapabilities"
# Service field declared in the IDL but not yet settable at creation is rejected as PropertyNotSupported,
# and the offending sub-property is identified
defer_transient_cleanup varlink-transient-unknown-service.service
unsupported_service=$(varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-unknown-service.service","Service":{"Type":"oneshot","Restart":"always","ExecStart":[{"path":"/bin/true"}]}}}' 2>&1 || true)
echo "$unsupported_service" | grep "io.systemd.Unit.PropertyNotSupported"
echo "$unsupported_service" | grep "Service.Restart"
set -o pipefail

transient_cleanup
trap - EXIT
