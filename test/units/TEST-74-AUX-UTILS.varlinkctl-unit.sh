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
# test for MountContext/Runtime
mount_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "mount" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
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
# test for ServiceContext/Runtime
service_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "service" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
test -n "$service_id"
service_params=$(jq -cn --arg name "$service_id" '{name: $name}')
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$service_params" | jq -e '.context.Service'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "$service_params" | jq -e '.runtime.Service'
# test for ScopeContext/Runtime
scope_id=$(varlinkctl call --collect /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' | jq -r '.[] | select(.context.Type == "scope" and .runtime.LoadState == "loaded") .context.ID // empty' | tail -n 1)
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
