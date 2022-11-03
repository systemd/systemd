#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

systemctl log-level debug

# Test that a path unit continuously triggering a service that fails condition checks eventually fails with
# the trigger-limit-hit error.
rm -f /tmp/nonexistent
systemctl start test63.path
touch /tmp/test63

# Make sure systemd has sufficient time to hit the trigger limit for test63.path.
sleep 2
test "$(systemctl show test63.service -P ActiveState)" = inactive
test "$(systemctl show test63.service -P Result)" = success
test "$(systemctl show test63.path -P ActiveState)" = failed
test "$(systemctl show test63.path -P Result)" = trigger-limit-hit

# Test that starting the service manually doesn't affect the path unit.
rm -f /tmp/test63
systemctl reset-failed
systemctl start test63.path
systemctl start test63.service
test "$(systemctl show test63.service -P ActiveState)" = inactive
test "$(systemctl show test63.service -P Result)" = success
test "$(systemctl show test63.path -P ActiveState)" = active
test "$(systemctl show test63.path -P Result)" = success

# Test that glob matching works too, with $TRIGGER_PATH
systemctl start test63-glob.path
touch /tmp/test63-glob-foo
timeout 60 bash -c 'while ! systemctl -q is-active test63-glob.service; do sleep .2; done'
test "$(systemctl show test63-glob.service -P ActiveState)" = active
test "$(systemctl show test63-glob.service -P Result)" = success

test "$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/test63_2dglob_2eservice org.freedesktop.systemd1.Unit ActivationDetails)" = '{"type":"a(ss)","data":[["trigger_unit","test63-glob.path"],["trigger_path","/tmp/test63-glob-foo"]]}'

systemctl stop test63-glob.path test63-glob.service

test "$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/test63_2dglob_2eservice org.freedesktop.systemd1.Unit ActivationDetails)" = '{"type":"a(ss)","data":[]}'

systemctl log-level info

echo OK >/testok
