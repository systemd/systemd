#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

at_exit() {
    if [[ -v UNIT_NAME && -e "/usr/lib/systemd/system/$UNIT_NAME" ]]; then
        rm -fv "/usr/lib/systemd/system/$UNIT_NAME"
    fi
}

trap at_exit EXIT

# Create a simple unit file for testing
# Note: the service file is created under /usr on purpose to test
#       the 'revert' verb as well
UNIT_NAME="systemctl-test-$RANDOM.service"
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

systemctl daemon-reload

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
systemctl list-unit-files
systemctl list-unit-files "*journal*"
systemctl list-jobs
systemctl list-jobs --after
systemctl list-jobs --before
systemctl list-jobs --after --before
systemctl list-jobs "*"

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

# enable/disable/preset
(! systemctl is-enabled "$UNIT_NAME")
systemctl enable "$UNIT_NAME"
systemctl is-enabled -l "$UNIT_NAME"
# We created a preset file for this unit above with a "disable" policy
systemctl preset "$UNIT_NAME"
(! systemctl is-enabled "$UNIT_NAME")
systemctl reenable "$UNIT_NAME"
systemctl is-enabled "$UNIT_NAME"
systemctl preset --preset-mode=enable-only "$UNIT_NAME"
systemctl is-enabled "$UNIT_NAME"
systemctl preset --preset-mode=disable-only "$UNIT_NAME"
(! systemctl is-enabled "$UNIT_NAME")
systemctl enable --runtime "$UNIT_NAME"
[[ -e "/run/systemd/system/multi-user.target.wants/$UNIT_NAME" ]]
systemctl is-enabled "$UNIT_NAME"
systemctl disable "$UNIT_NAME"
# The unit should be still enabled, as we didn't use the --runtime switch
systemctl is-enabled "$UNIT_NAME"
systemctl disable --runtime "$UNIT_NAME"
(! systemctl is-enabled "$UNIT_NAME")

# mask/unmask/revert
systemctl disable "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == disabled ]]
systemctl mask "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == masked ]]
systemctl unmask "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == disabled ]]
systemctl mask "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == masked ]]
systemctl revert "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == disabled ]]
systemctl mask --runtime "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == masked-runtime ]]
# This should be a no-op without the --runtime switch
systemctl unmask "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == masked-runtime ]]
systemctl unmask --runtime "$UNIT_NAME"
[[ "$(systemctl is-enabled "$UNIT_NAME")" == disabled ]]

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
target="$(systemctl get-default)"
systemctl set-default emergency.target
[[ "$(systemctl get-default)" == emergency.target ]]
systemctl set-default "$target"
[[ "$(systemctl get-default)" == "$target" ]]

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

echo OK >/testok

exit 0
