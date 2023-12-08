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

trap at_exit EXIT

# Create a simple unit file for testing
# Note: the service file is created under /usr on purpose to test
#       the 'revert' verb as well
export UNIT_NAME="systemctl-test-$RANDOM.service"
export UNIT_NAME2="systemctl-test-$RANDOM.service"

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
systemctl kill "$UNIT_NAME"
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
systemctl set-property --runtime "$UNIT_NAME" CPUAccounting=no CPUQuota=10%
systemctl cat "$UNIT_NAME"
grep -r "CPUAccounting=no" "/run/systemd/system.control/${UNIT_NAME}.d/"
grep -r "CPUQuota=10%" "/run/systemd/system.control/${UNIT_NAME}.d/"
systemctl revert "$UNIT_NAME"
(! grep -r "CPUAccounting=" "/run/systemd/system.control/${UNIT_NAME}.d/")
(! grep -r "CPUQuota=" "/run/systemd/system.control/${UNIT_NAME}.d/")

# Failed-unit related tests
(! systemd-run --wait --unit "failed.service" /bin/false)
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
systemctl status -a --state active,running,plugged >/dev/null
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
systemctl cat "*journal*"
systemctl cat "$UNIT_NAME"
systemctl help "$UNIT_NAME"
systemctl service-watchdogs
systemctl service-watchdogs "$(systemctl service-watchdogs)"

# show/set-environment
# Make sure PATH is set
systemctl show-environment | grep -q '^PATH='
# Let's add an entry and override a built-in one
systemctl set-environment PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/testaddition FOO=BAR
# Check that both are set
systemctl show-environment | grep -q '^PATH=.*testaddition$'
systemctl show-environment | grep -q '^FOO=BAR$'
systemctl daemon-reload
# Check again after the reload
systemctl show-environment | grep -q '^PATH=.*testaddition$'
systemctl show-environment | grep -q '^FOO=BAR$'
# Check that JSON output is supported
systemctl show-environment --output=json | grep -q '^{.*"FOO":"BAR".*}$'
# Drop both
systemctl unset-environment FOO PATH
# Check that one is gone and the other reverted to the built-in
systemctl show-environment | grep '^FOO=$' && exit 1
systemctl show-environment | grep '^PATH=.*testaddition$' && exit 1
systemctl show-environment | grep -q '^PATH='
# Check import-environment
export IMPORT_THIS=hello
export IMPORT_THIS_TOO=world
systemctl import-environment IMPORT_THIS IMPORT_THIS_TOO
systemctl show-environment | grep "^IMPORT_THIS=$IMPORT_THIS"
systemctl show-environment | grep "^IMPORT_THIS_TOO=$IMPORT_THIS_TOO"
systemctl unset-environment IMPORT_THIS IMPORT_THIS_TOO
(! systemctl show-environment | grep "^IMPORT_THIS=")
(! systemctl show-environment | grep "^IMPORT_THIS_TOO=")

# test for sysv-generator (issue #24990)
if [[ -x /usr/lib/systemd/system-generators/systemd-sysv-generator ]]; then
    # This is configurable via -Dsysvinit-path=, but we can't get the value
    # at runtime, so let's just support the two most common paths for now.
    [[ -d /etc/rc.d/init.d ]] && SYSVINIT_PATH="/etc/rc.d/init.d" || SYSVINIT_PATH="/etc/init.d"

    # invalid dependency
    cat >"${SYSVINIT_PATH:?}/issue-24990" <<\EOF
#!/bin/bash

### BEGIN INIT INFO
# Provides:test1 test2
# Required-Start:test1 $remote_fs $network
# Required-Stop:test1 $remote_fs $network
# Description:Test
# Short-Description: Test
### END INIT INFO

case "$1" in
    start)
        echo "Starting issue-24990.service"
        sleep 1000 &
        ;;
    stop)
        echo "Stopping issue-24990.service"
        sleep 10 &
        ;;
    *)
        echo "Usage: service test {start|stop|restart|status}"
        ;;
esac
EOF

    chmod +x "$SYSVINIT_PATH/issue-24990"
    systemctl daemon-reload
    [[ -L /run/systemd/generator.late/test1.service ]]
    [[ -L /run/systemd/generator.late/test2.service ]]
    assert_eq "$(readlink -f /run/systemd/generator.late/test1.service)" "/run/systemd/generator.late/issue-24990.service"
    assert_eq "$(readlink -f /run/systemd/generator.late/test2.service)" "/run/systemd/generator.late/issue-24990.service"
    output=$(systemctl cat issue-24990)
    assert_in "SourcePath=$SYSVINIT_PATH/issue-24990" "$output"
    assert_in "Description=LSB: Test" "$output"
    assert_in "After=test1.service" "$output"
    assert_in "After=remote-fs.target" "$output"
    assert_in "After=network-online.target" "$output"
    assert_in "Wants=network-online.target" "$output"
    assert_in "ExecStart=$SYSVINIT_PATH/issue-24990 start" "$output"
    assert_in "ExecStop=$SYSVINIT_PATH/issue-24990 stop" "$output"
    systemctl status issue-24990 || :
    systemctl show issue-24990
    assert_not_in "issue-24990.service" "$(systemctl show --property=After --value)"
    assert_not_in "issue-24990.service" "$(systemctl show --property=Before --value)"

    if ! systemctl is-active network-online.target; then
        systemctl start network-online.target
    fi

    systemctl restart issue-24990
    systemctl stop issue-24990

    # valid dependency
    cat >"$SYSVINIT_PATH/issue-24990" <<\EOF
#!/bin/bash

### BEGIN INIT INFO
# Provides:test1 test2
# Required-Start:$remote_fs
# Required-Stop:$remote_fs
# Description:Test
# Short-Description: Test
### END INIT INFO

case "$1" in
    start)
        echo "Starting issue-24990.service"
        sleep 1000 &
        ;;
    stop)
        echo "Stopping issue-24990.service"
        sleep 10 &
        ;;
    *)
        echo "Usage: service test {start|stop|restart|status}"
        ;;
esac
EOF

    chmod +x "$SYSVINIT_PATH/issue-24990"
    systemctl daemon-reload
    [[ -L /run/systemd/generator.late/test1.service ]]
    [[ -L /run/systemd/generator.late/test2.service ]]
    assert_eq "$(readlink -f /run/systemd/generator.late/test1.service)" "/run/systemd/generator.late/issue-24990.service"
    assert_eq "$(readlink -f /run/systemd/generator.late/test2.service)" "/run/systemd/generator.late/issue-24990.service"
    output=$(systemctl cat issue-24990)
    assert_in "SourcePath=$SYSVINIT_PATH/issue-24990" "$output"
    assert_in "Description=LSB: Test" "$output"
    assert_in "After=remote-fs.target" "$output"
    assert_in "ExecStart=$SYSVINIT_PATH/issue-24990 start" "$output"
    assert_in "ExecStop=$SYSVINIT_PATH/issue-24990 stop" "$output"
    systemctl status issue-24990 || :
    systemctl show issue-24990
    assert_not_in "issue-24990.service" "$(systemctl show --property=After --value)"
    assert_not_in "issue-24990.service" "$(systemctl show --property=Before --value)"

    systemctl restart issue-24990
    systemctl stop issue-24990
fi

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

touch /testok
