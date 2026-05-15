#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    if [[ -v UNIT_NAME && -e "/usr/lib/systemd/system/$UNIT_NAME" ]]; then
        rm -fvr "/usr/lib/systemd/system/$UNIT_NAME" "/etc/systemd/system/$UNIT_NAME.d" "+4"
    fi

    rm -f /etc/init.d/issue-24990
    return 0
}

# Create a simple unit file for testing
# Note: the service file is created under /usr on purpose to test
#       the 'revert' verb as well
export UNIT_NAME="systemctl-test-$RANDOM.service"
export UNIT_NAME2="systemctl-test-$RANDOM.service"
export UNIT_NAME_TEMPLATE="systemctl-test-${RANDOM}@.service"

cat >"/usr/lib/systemd/system/$UNIT_NAME" <<\EOF
[Unit]
Description=systemctl test

[Service]
ExecStart=sleep infinity
ExecReload=true

# For systemctl clean
CacheDirectory=%n
ConfigurationDirectory=%n
LogsDirectory=%n
RuntimeDirectory=%n
StateDirectory=%n

[Install]
WantedBy=multi-user.target
EOF

# Configure the preset setting for the unit file
mkdir /run/systemd/system-preset/
echo "disable $UNIT_NAME" >/run/systemd/system-preset/99-systemd-test.preset

EDITOR='true' script -ec 'systemctl edit "$UNIT_NAME"' /dev/null
[ ! -e "/etc/systemd/system/$UNIT_NAME.d/override.conf" ]

printf '%s\n' '[Service]' 'ExecStart=' 'ExecStart=sleep 10d' >"+4"
EDITOR='mv' script -ec 'systemctl edit "$UNIT_NAME"' /dev/null
printf '%s\n' '[Service]' 'ExecStart=' 'ExecStart=sleep 10d' | cmp - "/etc/systemd/system/$UNIT_NAME.d/override.conf"

printf '%b'   '[Service]\n' 'ExecStart=\n' 'ExecStart=sleep 10d' >"+4"
EDITOR='mv' script -ec 'systemctl edit "$UNIT_NAME"' /dev/null
printf '%s\n' '[Service]'   'ExecStart='   'ExecStart=sleep 10d' | cmp - "/etc/systemd/system/$UNIT_NAME.d/override.conf"

systemctl edit "$UNIT_NAME" --stdin --drop-in=override2.conf <<EOF
[Unit]
Description=spectacular
# this comment should remain

EOF
printf '%s\n' '[Unit]'   'Description=spectacular' '# this comment should remain' | \
    cmp - "/etc/systemd/system/$UNIT_NAME.d/override2.conf"

# Edit nonexistent template unit, see issue #35632.
systemctl edit "$UNIT_NAME_TEMPLATE" --stdin --runtime --force --full <<EOF
[Unit]
Description=template unit test
# this comment should remain

EOF
printf '%s\n' '[Unit]' 'Description=template unit test' '# this comment should remain' | \
    cmp - "/run/systemd/system/$UNIT_NAME_TEMPLATE"

# Test simultaneous editing of two units and creation of drop-in for a nonexistent unit
systemctl edit "$UNIT_NAME" "$UNIT_NAME2" --stdin --force --drop-in=override2.conf <<<'[X-Section]'
printf '%s\n' '[X-Section]' | cmp - "/etc/systemd/system/$UNIT_NAME.d/override2.conf"
printf '%s\n' '[X-Section]' | cmp - "/etc/systemd/system/$UNIT_NAME2.d/override2.conf"

# Double free when editing a template unit (#26483)
EDITOR='true' script -ec 'systemctl edit user@0' /dev/null

# Argument help
systemctl --state help
systemctl --signal help
systemctl --type help

# list-dependencies
systemctl list-dependencies systemd-journald
systemctl list-dependencies --after systemd-journald
systemctl list-dependencies --before systemd-journald
systemctl list-dependencies --after --reverse systemd-journald
systemctl list-dependencies --before --reverse systemd-journald
systemctl list-dependencies --plain systemd-journald

# list-* verbs
systemctl list-units
systemctl list-units --recursive
systemctl list-units --type=socket
systemctl list-units --type=service,timer
# Compat: --type= allows load states for compatibility reasons
systemctl list-units --type=loaded
systemctl list-units --type=loaded,socket
systemctl list-units --legend=yes -a "systemd-*"
systemctl list-units --state=active
systemctl list-units --with-dependencies systemd-journald.service
systemctl list-units --with-dependencies --after systemd-journald.service
systemctl list-units --with-dependencies --before --reverse systemd-journald.service
systemctl list-sockets
systemctl list-sockets --legend=no -a "*journal*"
systemctl list-sockets --show-types
systemctl list-sockets --state=listening
systemctl list-timers -a -l
systemctl list-jobs
systemctl list-jobs --after
systemctl list-jobs --before
systemctl list-jobs --after --before
systemctl list-jobs "*"
systemctl list-dependencies sysinit.target --type=socket,mount
systemctl list-dependencies multi-user.target --state=active
systemctl list-dependencies sysinit.target --state=mounted --all
systemctl list-paths
systemctl list-paths --legend=no -a "systemd*"

test_list_unit_files() {
    systemctl list-unit-files "$@"
    systemctl list-unit-files "$@" "*journal*"
}

test_list_unit_files
test_list_unit_files --root=/

# is-* verbs
# Should return 4 for a missing unit file
assert_rc 4 systemctl --quiet is-active not-found.service
assert_rc 4 systemctl --quiet is-failed not-found.service
assert_rc 4 systemctl --quiet is-enabled not-found.service
# is-active: return 3 when the unit exists but inactive
assert_rc 3 systemctl --quiet is-active "$UNIT_NAME"
# is-enabled: return 1 when the unit exists but disabled
assert_rc 1 systemctl --quiet is-enabled "$UNIT_NAME"

# Basic service management
systemctl start --show-transaction "$UNIT_NAME"
systemctl status -n 5 "$UNIT_NAME"
systemctl is-active "$UNIT_NAME"
systemctl reload -T "$UNIT_NAME"
systemctl restart -T "$UNIT_NAME"
systemctl try-restart --show-transaction "$UNIT_NAME"
systemctl try-reload-or-restart --show-transaction "$UNIT_NAME"
timeout 10 systemctl kill --wait "$UNIT_NAME"
(! systemctl is-active "$UNIT_NAME")
systemctl restart "$UNIT_NAME"
systemctl is-active "$UNIT_NAME"
systemctl restart "$UNIT_NAME"
systemctl stop "$UNIT_NAME"
(! systemctl is-active "$UNIT_NAME")

assert_eq "$(systemctl is-system-running)" "$(systemctl is-failed)"

# enable/disable/preset
test_enable_disable_preset() {
    (! systemctl is-enabled "$@" "$UNIT_NAME")
    systemctl enable "$@" "$UNIT_NAME"
    systemctl is-enabled "$@" -l "$UNIT_NAME"
    # We created a preset file for this unit above with a "disable" policy
    systemctl preset "$@" "$UNIT_NAME"
    (! systemctl is-enabled "$@" "$UNIT_NAME")
    systemctl reenable "$@" "$UNIT_NAME"
    systemctl is-enabled "$@" "$UNIT_NAME"
    systemctl preset "$@" --preset-mode=enable-only "$UNIT_NAME"
    systemctl is-enabled "$@" "$UNIT_NAME"
    systemctl preset "$@" --preset-mode=disable-only "$UNIT_NAME"
    (! systemctl is-enabled "$@" "$UNIT_NAME")
    systemctl enable "$@" --runtime "$UNIT_NAME"
    [[ -e "/run/systemd/system/multi-user.target.wants/$UNIT_NAME" ]]
    systemctl is-enabled "$@" "$UNIT_NAME"
    systemctl disable "$@" "$UNIT_NAME"
    # The unit should be still enabled, as we didn't use the --runtime switch
    systemctl is-enabled "$@" "$UNIT_NAME"
    systemctl disable "$@" --runtime "$UNIT_NAME"
    (! systemctl is-enabled "$@" "$UNIT_NAME")
}

test_enable_disable_preset
test_enable_disable_preset --root=/

# mask/unmask/revert
test_mask_unmask_revert() {
    systemctl disable "$@" "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == disabled ]]
    systemctl mask "$@" "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == masked ]]
    systemctl unmask "$@" "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == disabled ]]
    systemctl mask "$@" "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == masked ]]
    systemctl revert "$@" "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == disabled ]]
    systemctl mask "$@" --runtime "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == masked-runtime ]]
    # This should be a no-op without the --runtime switch
    systemctl unmask "$@" "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == masked-runtime ]]
    systemctl unmask "$@" --runtime "$UNIT_NAME"
    [[ "$(systemctl is-enabled "$@" "$UNIT_NAME")" == disabled ]]
}

test_mask_unmask_revert
test_mask_unmask_revert --root=/

# disable --now with template unit
cat >/run/systemd/system/test-disable@.service <<EOF
[Service]
ExecStart=sleep infinity

[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now test-disable@1.service test-disable@2.service
systemctl is-active test-disable@1.service
systemctl is-active test-disable@2.service
systemctl disable --now test-disable@.service
for u in test-disable@{1,2}.service; do
    (! systemctl is-active "$u")
    (! systemctl is-enabled "$u")
done
rm /run/systemd/system/test-disable@.service

# add-wants/add-requires
(! systemctl show -P Wants "$UNIT_NAME" | grep "systemd-journald.service")
systemctl add-wants "$UNIT_NAME" "systemd-journald.service"
systemctl show -P Wants "$UNIT_NAME" | grep "systemd-journald.service"
(! systemctl show -P Requires "$UNIT_NAME" | grep "systemd-journald.service")
systemctl add-requires "$UNIT_NAME" "systemd-journald.service"
systemctl show -P Requires "$UNIT_NAME" | grep "systemd-journald.service"

# set-property
systemctl set-property "$UNIT_NAME" IPAccounting=yes MemoryMax=1234567
systemctl cat "$UNIT_NAME"
# These properties should be saved to a persistent storage
grep -r "IPAccounting=yes" "/etc/systemd/system.control/${UNIT_NAME}.d/"
grep -r "MemoryMax=1234567" "/etc/systemd/system.control/${UNIT_NAME}.d"
systemctl revert "$UNIT_NAME"
(! grep -r "IPAccounting=" "/etc/systemd/system.control/${UNIT_NAME}.d/")
(! grep -r "MemoryMax=" "/etc/systemd/system.control/${UNIT_NAME}.d/")
# Same stuff, but with --runtime, which should use /run
systemctl set-property --runtime "$UNIT_NAME" IOAccounting=no CPUQuota=10%
systemctl cat "$UNIT_NAME"
grep -r "IOAccounting=no" "/run/systemd/system.control/${UNIT_NAME}.d/"
grep -r "CPUQuota=10.00%" "/run/systemd/system.control/${UNIT_NAME}.d/"
systemctl revert "$UNIT_NAME"
(! grep -r "IOAccounting=" "/run/systemd/system.control/${UNIT_NAME}.d/")
(! grep -r "CPUQuota=" "/run/systemd/system.control/${UNIT_NAME}.d/")

# Failed-unit related tests
(! systemd-run --wait --unit "failed.service" false)
systemctl is-failed failed.service
systemctl --state=failed | grep failed.service
systemctl --failed | grep failed.service
systemctl reset-failed "fail*.service"
(! systemctl is-failed failed.service)

# clean
systemctl restart "$UNIT_NAME"
systemctl stop "$UNIT_NAME"
# Check if the directories from *Directory= directives exist
# (except RuntimeDirectory= in /run, which is removed when the unit is stopped)
for path in /var/lib /var/cache /var/log /etc; do
    [[ -e "$path/$UNIT_NAME" ]]
done
# Run the cleanup
for what in "" configuration state cache logs runtime all; do
    systemctl clean ${what:+--what="$what"} "$UNIT_NAME"
done
# All respective directories should be removed
for path in /run /var/lib /var/cache /var/log /etc; do
    [[ ! -e "$path/$UNIT_NAME" ]]
done

# --timestamp
for value in pretty us µs utc us+utc µs+utc; do
    systemctl show -P KernelTimestamp --timestamp="$value"
done

# --timestamp with timer properties (issue #39282)
TIMER1="timestamp-test1-$RANDOM.timer"
SERVICE1="${TIMER1%.timer}.service"
cat >"/run/systemd/system/$SERVICE1" <<EOF
[Service]
Type=oneshot
ExecStart=true
EOF

cat >"/run/systemd/system/$TIMER1" <<EOF
[Timer]
OnCalendar=*-*-* 00:00:00
EOF

systemctl daemon-reload
systemctl start "$TIMER1"

output=$(systemctl show -P NextElapseUSecRealtime --timestamp=unix "$TIMER1")
if [[ ! "$output" =~ ^@[0-9]+$ ]]; then
    echo "NextElapseUSecRealtime: expected @<number> with --timestamp=unix, got: $output" >&2
    exit 1
fi

systemctl stop "$TIMER1"
rm -f "/run/systemd/system/$TIMER1" "/run/systemd/system/$SERVICE1"

TIMER2="timestamp-test2-$RANDOM.timer"
SERVICE2="${TIMER2%.timer}.service"
cat >"/run/systemd/system/$SERVICE2" <<EOF
[Service]
Type=oneshot
ExecStart=true
EOF

cat >"/run/systemd/system/$TIMER2" <<EOF
[Timer]
OnActiveSec=100ms
EOF

systemctl daemon-reload
systemctl start "$TIMER2"
sleep 0.5

output=$(systemctl show -P LastTriggerUSec --timestamp=unix "$TIMER2")
if [[ ! "$output" =~ ^@[0-9]+$ ]]; then
    echo "LastTriggerUSec: expected @<number> with --timestamp=unix, got: $output" >&2
    exit 1
fi

systemctl stop "$TIMER2"
rm -f "/run/systemd/system/$TIMER2" "/run/systemd/system/$SERVICE2"
systemctl daemon-reload

# set-default/get-default
test_get_set_default() {
    target="$(systemctl get-default "$@")"
    systemctl set-default "$@" emergency.target
    [[ "$(systemctl get-default "$@")" == emergency.target ]]
    systemctl set-default "$@" "$target"
    [[ "$(systemctl get-default "$@")" == "$target" ]]
}

test_get_set_default
test_get_set_default --root=/

# show/status
systemctl show --property ""
# Pick a heavily sandboxed unit for the best effect on coverage
systemctl show systemd-logind.service
systemctl status
# Ignore the exit code in this case, as it might try to load non-existing units
systemctl status -a >/dev/null || :
# Ditto - there is a window between the first ListUnitsByByPatterns and the querying of individual units in
# which some units might change their state (e.g. running -> stop-sigterm), which then causes systemctl to
# return EC > 0
systemctl status -a --state active,running,plugged >/dev/null || :
systemctl status "systemd-*.timer"
systemctl status "systemd-journald*.socket"
systemctl status "sys-devices-*-ttyS0.device"
systemctl status -- -.mount
systemctl status 1

# --marked
systemctl restart "$UNIT_NAME"
systemctl set-property "$UNIT_NAME" "Markers=needs-reload needs-restart"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-reload
systemctl reload-or-restart --marked
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-restart)
systemctl is-active "$UNIT_NAME"
systemctl set-property "$UNIT_NAME" "Markers=needs-reload needs-stop"
systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-reload
systemctl reload-or-restart --marked
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-stop)
(! systemctl is-active "$UNIT_NAME")
systemctl set-property "$UNIT_NAME" "Markers=needs-start"
systemctl show -P Markers "$UNIT_NAME" | grep needs-start
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-stop
systemctl reload-or-restart --marked
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-start)
systemctl is-active "$UNIT_NAME"
systemctl set-property "$UNIT_NAME" "Markers=needs-start needs-stop"
systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-start
systemctl reload-or-restart --marked
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-stop)
(! systemctl is-active "$UNIT_NAME")

# Test marker normalization with incremental (+) syntax

# needs-start + +needs-restart → needs-restart (restart wins against start)
systemctl set-property "$UNIT_NAME" "Markers=needs-start"
systemctl set-property "$UNIT_NAME" "Markers=+needs-restart"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-start)
systemctl set-property "$UNIT_NAME" "Markers="

# needs-restart + +needs-start → needs-restart (restart wins against start)
systemctl set-property "$UNIT_NAME" "Markers=needs-restart"
systemctl set-property "$UNIT_NAME" "Markers=+needs-start"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-start)
systemctl set-property "$UNIT_NAME" "Markers="

# needs-restart + +needs-reload → needs-restart (reload loses against restart)
systemctl set-property "$UNIT_NAME" "Markers=needs-restart"
systemctl set-property "$UNIT_NAME" "Markers=+needs-reload"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-reload)
systemctl set-property "$UNIT_NAME" "Markers="

# needs-stop + +needs-start → needs-start (start overrides stop)
systemctl set-property "$UNIT_NAME" "Markers=needs-stop"
systemctl set-property "$UNIT_NAME" "Markers=+needs-start"
systemctl show -P Markers "$UNIT_NAME" | grep needs-start
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-stop)
systemctl set-property "$UNIT_NAME" "Markers="

# anything + +needs-stop → needs-stop (stop wins against everything)
for marker in needs-start needs-restart needs-reload; do
    systemctl set-property "$UNIT_NAME" "Markers=$marker"
    systemctl set-property "$UNIT_NAME" "Markers=+needs-stop"
    systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
    (! systemctl show -P Markers "$UNIT_NAME" | grep "$marker")
    systemctl set-property "$UNIT_NAME" "Markers="
done

# needs-stop + +needs-reload → needs-stop (stop wins against reload)
systemctl set-property "$UNIT_NAME" "Markers=needs-stop"
systemctl set-property "$UNIT_NAME" "Markers=+needs-reload"
systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-reload)
systemctl set-property "$UNIT_NAME" "Markers="

# again, but with varlinkctl instead
systemctl restart "$UNIT_NAME"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-reload\", \"needs-restart\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-reload
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.EnqueueMarkedJobs '{}'
timeout 30 bash -c "until systemctl list-jobs $UNIT_NAME | grep \"No jobs\" 2>/dev/null; do sleep 1; done"
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-restart)
systemctl is-active "$UNIT_NAME"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-reload\", \"needs-stop\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-reload
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.EnqueueMarkedJobs '{}'
timeout 30 bash -c "until systemctl list-jobs $UNIT_NAME | grep \"No jobs\" 2>/dev/null; do sleep 1; done"
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-stop)
(! systemctl is-active "$UNIT_NAME")
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-start\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-start
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-stop
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.EnqueueMarkedJobs '{}'
timeout 30 bash -c "until systemctl list-jobs $UNIT_NAME | grep \"No jobs\" 2>/dev/null; do sleep 1; done"
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-start)
systemctl is-active "$UNIT_NAME"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-start\", \"needs-stop\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
systemctl show -P Markers "$UNIT_NAME" | grep -v needs-start
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.EnqueueMarkedJobs '{}'
timeout 30 bash -c "until systemctl list-jobs $UNIT_NAME | grep \"No jobs\" 2>/dev/null; do sleep 1; done"
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-stop)
(! systemctl is-active "$UNIT_NAME")

# Test marker normalization with incremental (+) syntax via varlinkctl

# needs-start + +needs-restart → needs-restart (restart wins against start)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-start\"]}}"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"+needs-restart\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-start)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": []}}"

# needs-restart + +needs-start → needs-restart (restart wins against start)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-restart\"]}}"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"+needs-start\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-start)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": []}}"

# needs-restart + +needs-reload → needs-restart (reload loses against restart)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-restart\"]}}"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"+needs-reload\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-reload)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": []}}"

# needs-stop + +needs-start → needs-start (start overrides stop)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-stop\"]}}"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"+needs-start\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-start
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-stop)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": []}}"

# anything + +needs-stop → needs-stop (stop wins against everything)
for marker in needs-start needs-restart needs-reload; do
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"$marker\"]}}"
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"+needs-stop\"]}}"
    systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
    (! systemctl show -P Markers "$UNIT_NAME" | grep "$marker")
    varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": []}}"
done

# needs-stop + +needs-reload → needs-stop (stop wins against reload)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-stop\"]}}"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"+needs-reload\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-stop
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-reload)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": []}}"

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

# Error cases: verify specific varlink error types
set +o pipefail
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-exists.service","Service":{"ExecStart":[{"path":"/usr/bin/sleep","arguments":["/usr/bin/sleep","infinity"]}]}}}' |& grep "io.systemd.Unit.UnitExists"
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-test.target","Description":"test"}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
defer_transient_cleanup varlink-transient-bad.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-bad.service","Service":{"Type":"simple"}}}' |& grep "io.systemd.Unit.BadUnitSetting"
# Invalid ExecStart path: exercises filename_or_absolute_path_is_valid() in transient_service_apply_properties()
defer_transient_cleanup varlink-transient-badpath.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-badpath.service","Service":{"Type":"simple","ExecStart":[{"path":""}]}}}' |& grep "io.systemd.Unit.BadUnitSetting"
# Relative WorkingDirectory path is rejected
defer_transient_cleanup varlink-transient-bad-wd.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-bad-wd.service","Exec":{"WorkingDirectory":{"path":"relative/path","missingOK":false}},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' |& grep "io.systemd.Unit.BadUnitSetting"
# Malformed environment entry (not KEY=VALUE)
defer_transient_cleanup varlink-transient-bad-env.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-bad-env.service","Exec":{"Environment":["not_an_env_var"]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' |& grep "io.systemd.Unit.BadUnitSetting"
# Invalid credential ID
defer_transient_cleanup varlink-transient-bad-cred-id.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-bad-cred-id.service","Exec":{"SetCredential":[{"id":"bad/id","value":"YWJj"}]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' |& grep "io.systemd.Unit.BadUnitSetting"
# Invalid base64 value for credential (rejected at JSON dispatch time as a parameter error)
defer_transient_cleanup varlink-transient-bad-cred-value.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-bad-cred-value.service","Exec":{"SetCredential":[{"id":"mycred","value":"!!!not_base64!!!"}]},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' |& grep "Invalid argument"
# Exec on a unit type without an exec context (.slice) is rejected
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-exec.slice","Exec":{"WorkingDirectory":{"path":"/tmp","missingOK":false}}}}' |& grep "io.systemd.Unit.UnitTypeNotSupported"
# Unknown field in Exec is rejected as PropertyNotSupported
defer_transient_cleanup varlink-transient-unknown-exec.service
varlinkctl call "$MANAGER_SOCKET" io.systemd.Unit.StartTransient \
    '{"context":{"ID":"varlink-transient-unknown-exec.service","Exec":{"RootDirectory":"/tmp"},"Service":{"Type":"oneshot","ExecStart":[{"path":"/bin/true"}]}}}' |& grep "io.systemd.Unit.PropertyNotSupported"
set -o pipefail

transient_cleanup
trap - EXIT

# --dry-run with destructive verbs
# kexec is skipped intentionally, as it requires a bit more involved setup
VERBS=(
    default
    emergency
    exit
    halt
    hibernate
    hybrid-sleep
    poweroff
    reboot
    rescue
    suspend
    suspend-then-hibernate
)

for verb in "${VERBS[@]}"; do
    systemctl --dry-run "$verb"

    if [[ "$verb" =~ (halt|poweroff|reboot) ]]; then
        systemctl --dry-run --message "Hello world" "$verb"
        systemctl --dry-run --no-wall "$verb"
        systemctl --dry-run -f "$verb"
        systemctl --dry-run -ff "$verb"
    fi
done

# Aux verbs & assorted checks
systemctl is-active "*-journald.service"
systemctl cat "*udevd*"
systemctl cat "$UNIT_NAME"
(! systemctl cat hopefully-nonexistent-unit.service)
systemctl cat --force hopefully-nonexistent-unit.service
systemctl help "$UNIT_NAME"
systemctl service-watchdogs
systemctl service-watchdogs "$(systemctl service-watchdogs)"
# Ensure that the enablement symlinks can still be removed after the user is gone, to avoid having leftovers
systemctl enable "$UNIT_NAME"
systemctl stop "$UNIT_NAME"
rm -f "/usr/lib/systemd/system/$UNIT_NAME"
systemctl daemon-reload
systemctl disable "$UNIT_NAME"

# show/set-environment
# Make sure PATH is set
systemctl show-environment | grep '^PATH=' >/dev/null
# Let's add an entry and override a built-in one
systemctl set-environment PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/testaddition FOO=BAR
# Check that both are set
systemctl show-environment | grep '^PATH=.*testaddition$' >/dev/null
systemctl show-environment | grep '^FOO=BAR$' >/dev/null
systemctl daemon-reload
# Check again after the reload
systemctl show-environment | grep '^PATH=.*testaddition$' >/dev/null
systemctl show-environment | grep '^FOO=BAR$' >/dev/null
# Check that JSON output is supported
systemctl show-environment --output=json | grep '^{.*"FOO":"BAR".*}$' >/dev/null
# Drop both
systemctl unset-environment FOO PATH
# Check that one is gone and the other reverted to the built-in
systemctl show-environment | grep '^FOO=$' && exit 1
systemctl show-environment | grep '^PATH=.*testaddition$' && exit 1
systemctl show-environment | grep '^PATH=' >/dev/null
# Check import-environment
export IMPORT_THIS=hello
export IMPORT_THIS_TOO=world
systemctl import-environment IMPORT_THIS IMPORT_THIS_TOO
systemctl show-environment | grep "^IMPORT_THIS=$IMPORT_THIS"
systemctl show-environment | grep "^IMPORT_THIS_TOO=$IMPORT_THIS_TOO"
systemctl unset-environment IMPORT_THIS IMPORT_THIS_TOO
(! systemctl show-environment | grep "^IMPORT_THIS=")
(! systemctl show-environment | grep "^IMPORT_THIS_TOO=")

# %J in WantedBy= causes ABRT (#26467)
cat >/run/systemd/system/test-WantedBy.service <<EOF
[Service]
ExecStart=true

[Install]
WantedBy=user-%i@%J.service
EOF
systemctl daemon-reload
systemctl enable --now test-WantedBy.service || :
systemctl daemon-reload

# Test systemctl edit --global and systemctl cat --global (issue #31272)
GLOBAL_UNIT_NAME="systemctl-test-$RANDOM.service"
GLOBAL_MASKED_UNIT="systemctl-test-masked-$RANDOM.service"

# Test 1: Create a new global user unit with --force and --runtime
systemctl edit --global --runtime --stdin --full --force "$GLOBAL_UNIT_NAME" <<EOF
[Unit]
Description=Test global unit

[Service]
ExecStart=/bin/true
EOF

# Verify the unit file was created in /run/systemd/user/
test -f "/run/systemd/user/$GLOBAL_UNIT_NAME"

# Test 2: Read the global unit with systemctl cat --global
systemctl cat --global "$GLOBAL_UNIT_NAME" | grep "ExecStart=/bin/true" >/dev/null

# Test 3: Edit existing global unit (add a drop-in)
systemctl edit --global --runtime --stdin "$GLOBAL_UNIT_NAME" <<EOF
[Service]
Environment=TEST=value
EOF

# Verify drop-in was created
test -f "/run/systemd/user/$GLOBAL_UNIT_NAME.d/override.conf"
systemctl cat --global "$GLOBAL_UNIT_NAME" | grep "Environment=TEST=value" >/dev/null

# Test 4: Create a masked global unit in /run/
mkdir -p /run/systemd/user
ln -sf /dev/null "/run/systemd/user/$GLOBAL_MASKED_UNIT"

# Test 5: Verify cat shows it's masked
systemctl cat --global "$GLOBAL_MASKED_UNIT" 2>&1 | grep "masked" >/dev/null

# Test 6: Verify edit refuses to edit masked unit
(! systemctl edit --global --runtime --stdin --full "$GLOBAL_MASKED_UNIT" </dev/null 2>&1) | grep "masked" >/dev/null

# Cleanup global test units
rm -f "/run/systemd/user/$GLOBAL_UNIT_NAME"
rm -rf "/run/systemd/user/$GLOBAL_UNIT_NAME.d"
rm -f "/run/systemd/user/$GLOBAL_MASKED_UNIT"

touch /testok
