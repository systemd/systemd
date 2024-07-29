#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemctl log-level debug

# Test that a path unit continuously triggering a service that fails condition checks eventually fails with
# the trigger-limit-hit error.
rm -f /tmp/nonexistent
systemctl start test63.path
touch /tmp/test63

# Make sure systemd has sufficient time to hit the trigger limit for test63.path.
# shellcheck disable=SC2016
timeout 30 bash -c 'until test "$(systemctl show test63.path -P ActiveState)" = failed; do sleep .2; done'
test "$(systemctl show test63.service -P ActiveState)" = inactive
test "$(systemctl show test63.service -P Result)" = success
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
timeout 60 bash -c 'until systemctl -q is-active test63-glob.service; do sleep .2; done'
test "$(systemctl show test63-glob.service -P ActiveState)" = active
test "$(systemctl show test63-glob.service -P Result)" = success

test "$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/test63_2dglob_2eservice org.freedesktop.systemd1.Unit ActivationDetails)" = '{"type":"a(ss)","data":[["trigger_unit","test63-glob.path"],["trigger_path","/tmp/test63-glob-foo"]]}'

systemctl stop test63-glob.path test63-glob.service

test "$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/test63_2dglob_2eservice org.freedesktop.systemd1.Unit ActivationDetails)" = '{"type":"a(ss)","data":[]}'

# tests for issue https://github.com/systemd/systemd/issues/24577#issuecomment-1522628906
rm -f /tmp/hoge
systemctl start test63-issue-24577.path
systemctl status -n 0 test63-issue-24577.path
systemctl status -n 0 test63-issue-24577.service || :
systemctl list-jobs
output=$(systemctl list-jobs --no-legend)
assert_not_in "test63-issue-24577.service" "$output"
assert_not_in "test63-issue-24577-dep.service" "$output"

touch /tmp/hoge
systemctl status -n 0 test63-issue-24577.path
systemctl status -n 0 test63-issue-24577.service || :
systemctl list-jobs
output=$(systemctl list-jobs --no-legend)
assert_in "test63-issue-24577.service" "$output"
assert_in "test63-issue-24577-dep.service" "$output"

# even if the service is stopped, it will be soon retriggered.
systemctl stop test63-issue-24577.service
systemctl status -n 0 test63-issue-24577.path
systemctl status -n 0 test63-issue-24577.service || :
systemctl list-jobs
output=$(systemctl list-jobs --no-legend)
assert_in "test63-issue-24577.service" "$output"
assert_in "test63-issue-24577-dep.service" "$output"

rm -f /tmp/hoge
systemctl stop test63-issue-24577.service
systemctl status -n 0 test63-issue-24577.path
systemctl status -n 0 test63-issue-24577.service || :
systemctl list-jobs
output=$(systemctl list-jobs --no-legend)
assert_not_in "test63-issue-24577.service" "$output"
assert_in "test63-issue-24577-dep.service" "$output"

# Test for race condition fixed by https://github.com/systemd/systemd/pull/30768
# Here's the schedule of events that we to happen during this test:
#       (This test)                     (The service)
#                                       .path unit monitors /tmp/copyme for changes
#       Take lock on /tmp/noexeit       ↓
#       Write to /tmp/copyme            ↓
#       Wait for deactivating           Started
#       ↓                               Copies /tmp/copyme to /tmp/copied
#       ↓                               Tells manager it's shutting down
#       Ensure service did the copy     Tries to lock /tmp/noexit and blocks
#       Write to /tmp/copyme            ↓
#
# Now at this point the test can diverge. If we regress, this second write is
# missed and we'll see:
#       ... (second write)              ... (blocked)
#       Drop lock on /tmp/noexit        ↓
#       Wait for service to do copy     Unblocks and exits
#       ↓                               (dead)
#       ↓
#       (timeout)
#       Test fails
#
# Otherwise, we'll see:
#       ... (second write)              ... (blocked)
#       Drop lock on /tmp/noexit        ↓ and .path unit queues a new start job
#       Wait for service to do copy     Unblocks and exits
#       ↓                               Starts again b/c of queued job
#       ↓                               Copies again
#       Test Passes
systemctl start test63-pr-30768.path
exec {lock}<>/tmp/noexit
flock -e $lock
echo test1 > /tmp/copyme
# shellcheck disable=SC2016
timeout 30 bash -c 'until test "$(systemctl show test63-pr-30768.service -P ActiveState)" = deactivating; do sleep .2; done'
diff /tmp/copyme /tmp/copied
echo test2 > /tmp/copyme
exec {lock}<&-
timeout 30 bash -c 'until diff /tmp/copyme /tmp/copied >/dev/null; do sleep .2; done'

systemctl log-level info

touch /testok
