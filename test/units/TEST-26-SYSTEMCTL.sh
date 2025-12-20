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
systemctl set-property "$UNIT_NAME" Markers=needs-restart
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
systemctl reload-or-restart --marked
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-restart)

# again, but with varlinkctl instead
systemctl restart "$UNIT_NAME"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties "{\"runtime\": true, \"name\": \"$UNIT_NAME\", \"properties\": {\"Markers\": [\"needs-restart\"]}}"
systemctl show -P Markers "$UNIT_NAME" | grep needs-restart
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.EnqueueMarkedJobs '{}'
timeout 30 bash -c "until systemctl list-jobs $UNIT_NAME | grep \"No jobs\" 2>/dev/null; do sleep 1; done"
(! systemctl show -P Markers "$UNIT_NAME" | grep needs-restart)

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
