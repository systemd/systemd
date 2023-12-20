#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-run --help --no-pager
systemd-run --version
systemd-run --no-ask-password true
systemd-run --no-block --collect true

export PARENT_FOO=bar
touch /tmp/public-marker

: "Transient service (system daemon)"
systemd-run --wait --pipe \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/run-.+\.service$ ]]'
systemd-run --wait --pipe --system \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/run-.+\.service$ ]]'
systemd-run --wait --pipe --slice=foo \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /foo\.slice/run-.+\.service$ ]]'
systemd-run --wait --pipe --slice=foo.slice \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /foo\.slice/run-.+\.service$ ]]'
systemd-run --wait --pipe --slice-inherit \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/run-.+\.service$ ]]'
systemd-run --wait --pipe --slice-inherit --slice=foo \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/system-foo\.slice/run-.+\.service$ ]]'
# We should not inherit caller's environment
systemd-run --wait --pipe bash -xec '[[ -z "$PARENT_FOO" ]]'
systemd-run --wait --pipe bash -xec '[[ "$PWD" == / && -n "$INVOCATION_ID" ]]'
systemd-run --wait --pipe \
            --send-sighup \
            --working-directory="" \
            --working-directory=/tmp \
            bash -xec '[[ "$PWD" == /tmp ]]'
systemd-run --wait --pipe --same-dir bash -xec "[[ \"\$PWD\" == $PWD ]]"
systemd-run --wait --pipe \
            --property=LimitCORE=1M:2M \
            --property=LimitCORE=16M:32M \
            --property=PrivateTmp=yes \
            bash -xec '[[ "$(ulimit -c -S)" -eq 16384 && "$(ulimit -c -H)" -eq 32768 && ! -e /tmp/public-marker ]]'
systemd-run --wait --pipe \
            --uid=testuser \
            bash -xec '[[ "$(id -nu)" == testuser && "$(id -ng)" == testuser ]]'
systemd-run --wait --pipe \
            --gid=testuser \
            bash -xec '[[ "$(id -nu)" == root && "$(id -ng)" == testuser ]]'
systemd-run --wait --pipe \
            --uid=testuser \
            --gid=root \
            bash -xec '[[ "$(id -nu)" == testuser && "$(id -ng)" == root ]]'
systemd-run --wait --pipe --expand-environment=no \
            --nice=10 \
            bash -xec 'read -r -a SELF_STAT </proc/self/stat && [[ "${SELF_STAT[18]}" -eq 10 ]]'
systemd-run --wait --pipe \
            --setenv=ENV_HELLO="nope" \
            --setenv=ENV_HELLO="env world" \
            --setenv=EMPTY= \
            --setenv=PARENT_FOO \
            --property=Environment="ALSO_HELLO='also world'" \
            bash -xec '[[ "$ENV_HELLO" == "env world" && -z "$EMPTY" && "$PARENT_FOO" == bar && "$ALSO_HELLO" == "also world" ]]'

UNIT="service-0-$RANDOM"
systemd-run --remain-after-exit --unit="$UNIT" \
            --service-type=simple \
            --service-type=oneshot \
            true
systemctl cat "$UNIT"
grep -q "^Type=oneshot" "/run/systemd/transient/$UNIT.service"
systemctl stop "$UNIT"
(! systemctl cat "$UNIT")

: "Transient service (user daemon)"
systemd-run --wait --pipe --user --machine=testuser@ \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /user\.slice/.+/run-.+\.service$ ]]'
systemd-run --wait --pipe --user --machine=testuser@ \
            bash -xec '[[ "$(id -nu)" == testuser && "$(id -ng)" == testuser ]]'
systemd-run --wait --pipe --user --machine=testuser@ \
            bash -xec '[[ "$PWD" == /home/testuser && -n "$INVOCATION_ID" ]]'
systemd-run --wait --pipe --user --machine=testuser@ \
            --property=LimitCORE=1M:2M \
            --property=LimitCORE=16M:32M \
            --property=PrivateTmp=yes \
            bash -xec '[[ "$(ulimit -c -S)" -eq 16384 && "$(ulimit -c -H)" -eq 32768 && ! -e /tmp/public-marker ]]'

: "Transient scope (system daemon)"
systemd-run --scope \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/run-.+\.scope$ ]]'
systemd-run --scope --system \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/run-.+\.scope$ ]]'
systemd-run --scope --slice=foo \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /foo\.slice/run-.+\.scope$ ]]'
systemd-run --scope --slice=foo.slice \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /foo\.slice/run-.+\.scope$ ]]'
systemd-run --scope --slice-inherit \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/run-.+\.scope$ ]]'
systemd-run --scope --slice-inherit --slice=foo \
            bash -xec '[[ "$(</proc/self/cgroup)" =~ /system\.slice/system-foo\.slice/run-.+\.scope$ ]]'
# We should inherit caller's environment
systemd-run --scope bash -xec '[[ "$PARENT_FOO" == bar ]]'
systemd-run --scope \
            --property=RuntimeMaxSec=10 \
            --property=RuntimeMaxSec=infinity \
            true

: "Transient scope (user daemon)"
# FIXME: https://github.com/systemd/systemd/issues/27883
#systemd-run --scope --user --machine=testuser@ \
#            bash -xec '[[ "$(</proc/self/cgroup)" =~ /user\.slice/run-.+\.scope$ ]]'
# We should inherit caller's environment
#systemd-run --scope --user --machine=testuser@ bash -xec '[[ "$PARENT_FOO" == bar ]]'

: "Transient timer unit"
UNIT="timer-0-$RANDOM"
systemd-run --remain-after-exit \
            --unit="$UNIT" \
            --timer-property=OnUnitInactiveSec=16h \
            true
systemctl cat "$UNIT.service" "$UNIT.timer"
grep -q "^OnUnitInactiveSec=16h$" "/run/systemd/transient/$UNIT.timer"
grep -qE "^ExecStart=.*/bin/true.*$" "/run/systemd/transient/$UNIT.service"
systemctl stop "$UNIT.timer" "$UNIT.service" || :

UNIT="timer-1-$RANDOM"
systemd-run --remain-after-exit \
            --unit="$UNIT" \
            --on-active=10 \
            --on-active=30s \
            --on-boot=1s \
            --on-startup=2m \
            --on-unit-active=3h20m \
            --on-unit-inactive="5d 4m 32s" \
            --on-calendar="mon,fri *-1/2-1,3 *:30:45" \
            --on-clock-change \
            --on-clock-change \
            --on-timezone-change \
            --timer-property=After=systemd-journald.service \
            --description="Hello world" \
            --description="My Fancy Timer" \
            true
systemctl cat "$UNIT.service" "$UNIT.timer"
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/$UNIT.service"
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/$UNIT.timer"
grep -q "^Description=My Fancy Timer$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnActiveSec=10s$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnActiveSec=30s$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnBootSec=1s$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnStartupSec=2min$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnUnitActiveSec=3h 20min$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnUnitInactiveSec=5d 4min 32s$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnCalendar=mon,fri \*\-1/2\-1,3 \*:30:45$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnClockChange=yes$" "/run/systemd/transient/$UNIT.timer"
grep -q "^OnTimezoneChange=yes$" "/run/systemd/transient/$UNIT.timer"
grep -q "^After=systemd-journald.service$" "/run/systemd/transient/$UNIT.timer"
grep -q "^Description=My Fancy Timer$" "/run/systemd/transient/$UNIT.service"
grep -q "^RemainAfterExit=yes$" "/run/systemd/transient/$UNIT.service"
grep -qE "^ExecStart=.*/bin/true.*$" "/run/systemd/transient/$UNIT.service"
(! grep -q "^After=systemd-journald.service$" "/run/systemd/transient/$UNIT.service")
systemctl stop "$UNIT.timer" "$UNIT.service" || :

: "Transient path unit"
UNIT="path-0-$RANDOM"
systemd-run --remain-after-exit \
            --unit="$UNIT" \
            --path-property=PathExists=/tmp \
            --path-property=PathExists=/tmp/foo \
            --path-property=PathChanged=/root/bar \
            true
systemctl cat "$UNIT.service" "$UNIT.path"
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/$UNIT.service"
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/$UNIT.path"
grep -q "^PathExists=/tmp$" "/run/systemd/transient/$UNIT.path"
grep -q "^PathExists=/tmp/foo$" "/run/systemd/transient/$UNIT.path"
grep -q "^PathChanged=/root/bar$" "/run/systemd/transient/$UNIT.path"
grep -qE "^ExecStart=.*/bin/true.*$" "/run/systemd/transient/$UNIT.service"
systemctl stop "$UNIT.path" "$UNIT.service" || :

: "Transient socket unit"
UNIT="socket-0-$RANDOM"
systemd-run --remain-after-exit \
            --unit="$UNIT" \
            --socket-property=ListenFIFO=/tmp/socket.fifo \
            --socket-property=SocketMode=0666 \
            --socket-property=SocketMode=0644 \
            true
systemctl cat "$UNIT.service" "$UNIT.socket"
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/$UNIT.service"
systemd-analyze verify --recursive-errors=no "/run/systemd/transient/$UNIT.socket"
grep -q "^ListenFIFO=/tmp/socket.fifo$" "/run/systemd/transient/$UNIT.socket"
grep -q "^SocketMode=0666$" "/run/systemd/transient/$UNIT.socket"
grep -q "^SocketMode=0644$" "/run/systemd/transient/$UNIT.socket"
grep -qE "^ExecStart=.*/bin/true.*$" "/run/systemd/transient/$UNIT.service"
systemctl stop "$UNIT.socket" "$UNIT.service" || :

: "Interactive options"
SHELL=/bin/true systemd-run --shell
SHELL=/bin/true systemd-run --scope --shell
systemd-run --wait --pty true
systemd-run --wait --machine=.host --pty true
(! SHELL=/bin/false systemd-run --quiet --shell)

(! systemd-run)
(! systemd-run "")
(! systemd-run --foo=bar)
(! systemd-run --wait --pipe --slice=foo.service true)

for opt in nice on-{active,boot,calendar,startup,unit-active,unit-inactive} property service-type setenv; do
    (! systemd-run "--$opt=" true)
    (! systemd-run "--$opt=''" true)
done

# Let's make sure that ProtectProc= properly moves submounts of the original /proc over to the new proc

A=$(cat /proc/sys/kernel/random/boot_id)
B=$(systemd-run -q --wait --pipe -p ProtectProc=invisible cat /proc/sys/kernel/random/boot_id)
assert_eq "$A" "$B"

V="/tmp/version.$RANDOM"
A="$(cat /proc/version).piff"
echo "$A" > "$V"
mount --bind "$V" /proc/version

B=$(systemd-run -q --wait --pipe -p ProtectProc=invisible cat /proc/version)

assert_eq "$A" "$B"

# Check that invoking the tool under the uid0 alias name works
uid0 ls /
echo "$(uid0 echo foo)" = "foo"

umount /proc/version
rm "$V"
