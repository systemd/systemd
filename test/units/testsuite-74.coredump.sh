#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Make sure the binary name fits into 15 characters
CORE_TEST_BIN="/tmp/test-dump"
CORE_TEST_UNPRIV_BIN="/tmp/test-usr-dump"
MAKE_DUMP_SCRIPT="/tmp/make-dump"
# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

at_exit() {
    rm -fv -- "$CORE_TEST_BIN" "$CORE_TEST_UNPRIV_BIN" "$MAKE_DUMP_SCRIPT"
}

trap at_exit EXIT

if systemd-detect-virt -cq; then
    echo "Running in a container, skipping the systemd-coredump test..."
    exit 0
fi

# Check that we're the ones to receive coredumps
sysctl kernel.core_pattern | grep systemd-coredump

# Prepare "fake" binaries for coredumps, so we can properly exercise
# the matching stuff too
cp -vf /bin/sleep "${CORE_TEST_BIN:?}"
cp -vf /bin/sleep "${CORE_TEST_UNPRIV_BIN:?}"
# Simple script that spawns given "fake" binary and then kills it with
# given signal
cat >"${MAKE_DUMP_SCRIPT:?}" <<\EOF
#!/bin/bash -ex

bin="${1:?}"
sig="${2:?}"

ulimit -c unlimited
"$bin" infinity &
pid=$!
sleep 1
kill -s "$sig" "$pid"
# This should always fail
! wait "$pid"
EOF
chmod +x "$MAKE_DUMP_SCRIPT"

# Privileged stuff
[[ "$(id -u)" -eq 0 ]]
# Trigger a couple of coredumps
"$MAKE_DUMP_SCRIPT" "$CORE_TEST_BIN" "SIGTRAP"
"$MAKE_DUMP_SCRIPT" "$CORE_TEST_BIN" "SIGABRT"
# In the tests we store the coredumps in journals, so let's generate a couple
# with Storage=external as well
mkdir -p /run/systemd/coredump.conf.d/
printf '[Coredump]\nStorage=external' >/run/systemd/coredump.conf.d/99-external.conf
"$MAKE_DUMP_SCRIPT" "$CORE_TEST_BIN" "SIGTRAP"
"$MAKE_DUMP_SCRIPT" "$CORE_TEST_BIN" "SIGABRT"
rm -fv /run/systemd/coredump.conf.d/99-external.conf
# Wait a bit for the coredumps to get processed
timeout 30 bash -c "while [[ \$(coredumpctl list -q --no-legend $CORE_TEST_BIN | wc -l) -lt 4 ]]; do sleep 1; done"

coredumpctl
SYSTEMD_LOG_LEVEL=debug coredumpctl
coredumpctl --help
coredumpctl --version
coredumpctl --no-pager --no-legend
coredumpctl --all
coredumpctl -1
coredumpctl -n 1
coredumpctl --reverse
coredumpctl -F COREDUMP_EXE
coredumpctl --json=short | jq
coredumpctl --json=pretty | jq
coredumpctl --json=off
coredumpctl --root=/
coredumpctl --directory=/var/log/journal
coredumpctl --file="/var/log/journal/$(</etc/machine-id)/system.journal"
coredumpctl --since=@0
coredumpctl --since=yesterday --until=tomorrow
# We should have a couple of externally stored coredumps
coredumpctl --field=COREDUMP_FILENAME | tee /tmp/coredumpctl.out
grep "/var/lib/systemd/coredump/core" /tmp/coredumpctl.out
rm -f /tmp/coredumpctl.out

coredumpctl info
coredumpctl info "$CORE_TEST_BIN"
coredumpctl info /foo /bar/ /baz "$CORE_TEST_BIN"
coredumpctl info "${CORE_TEST_BIN##*/}"
coredumpctl info foo bar baz "${CORE_TEST_BIN##*/}"
coredumpctl info COREDUMP_EXE="$CORE_TEST_BIN"
coredumpctl info COREDUMP_EXE=aaaaa COREDUMP_EXE= COREDUMP_EXE="$CORE_TEST_BIN"

coredumpctl debug --debugger=/bin/true "$CORE_TEST_BIN"
SYSTEMD_DEBUGGER=/bin/true coredumpctl debug "$CORE_TEST_BIN"
coredumpctl debug --debugger=/bin/true --debugger-arguments="-this --does --not 'do anything' -a -t --all" "${CORE_TEST_BIN##*/}"

coredumpctl dump "$CORE_TEST_BIN" >/tmp/core.redirected
test -s /tmp/core.redirected
coredumpctl dump -o /tmp/core.output "${CORE_TEST_BIN##*/}"
test -s /tmp/core.output
rm -f /tmp/core.{output,redirected}

# Unprivileged stuff
# Related issue: https://github.com/systemd/systemd/issues/26912
UNPRIV_CMD=(systemd-run --user --wait --pipe -M "testuser@.host" --)
# Trigger a couple of coredumps as an unprivileged user
"${UNPRIV_CMD[@]}" "$MAKE_DUMP_SCRIPT" "$CORE_TEST_UNPRIV_BIN" "SIGTRAP"
"${UNPRIV_CMD[@]}" "$MAKE_DUMP_SCRIPT" "$CORE_TEST_UNPRIV_BIN" "SIGABRT"
# In the tests we store the coredumps in journals, so let's generate a couple
# with Storage=external as well
mkdir -p /run/systemd/coredump.conf.d/
printf '[Coredump]\nStorage=external' >/run/systemd/coredump.conf.d/99-external.conf
"${UNPRIV_CMD[@]}" "$MAKE_DUMP_SCRIPT" "$CORE_TEST_UNPRIV_BIN" "SIGTRAP"
"${UNPRIV_CMD[@]}" "$MAKE_DUMP_SCRIPT" "$CORE_TEST_UNPRIV_BIN" "SIGABRT"
rm -fv /run/systemd/coredump.conf.d/99-external.conf
# Wait a bit for the coredumps to get processed
timeout 30 bash -c "while [[ \$(coredumpctl list -q --no-legend $CORE_TEST_UNPRIV_BIN | wc -l) -lt 4 ]]; do sleep 1; done"

# root should see coredumps from both binaries
coredumpctl info "$CORE_TEST_UNPRIV_BIN"
coredumpctl info "${CORE_TEST_UNPRIV_BIN##*/}"
# The test user should see only their own coredumps
"${UNPRIV_CMD[@]}" coredumpctl
"${UNPRIV_CMD[@]}" coredumpctl info "$CORE_TEST_UNPRIV_BIN"
"${UNPRIV_CMD[@]}" coredumpctl info "${CORE_TEST_UNPRIV_BIN##*/}"
(! "${UNPRIV_CMD[@]}" coredumpctl info --all "$CORE_TEST_BIN")
(! "${UNPRIV_CMD[@]}" coredumpctl info --all "${CORE_TEST_BIN##*/}")
# We should have a couple of externally stored coredumps
"${UNPRIV_CMD[@]}" coredumpctl --field=COREDUMP_FILENAME | tee /tmp/coredumpctl.out
grep "/var/lib/systemd/coredump/core" /tmp/coredumpctl.out
rm -f /tmp/coredumpctl.out

"${UNPRIV_CMD[@]}" coredumpctl debug --debugger=/bin/true "$CORE_TEST_UNPRIV_BIN"
"${UNPRIV_CMD[@]}" coredumpctl debug --debugger=/bin/true --debugger-arguments="-this --does --not 'do anything' -a -t --all" "${CORE_TEST_UNPRIV_BIN##*/}"

"${UNPRIV_CMD[@]}" coredumpctl dump "$CORE_TEST_UNPRIV_BIN" >/tmp/core.redirected
test -s /tmp/core.redirected
"${UNPRIV_CMD[@]}" coredumpctl dump -o /tmp/core.output "${CORE_TEST_UNPRIV_BIN##*/}"
test -s /tmp/core.output
rm -f /tmp/core.{output,redirected}
(! "${UNPRIV_CMD[@]}" coredumpctl dump "$CORE_TEST_BIN" >/dev/null)

# --backtrace mode
# Pass one of the existing journal coredump records to systemd-coredump and
# use our PID as the source to make matching the coredump later easier
# systemd-coredump args: PID UID GID SIGNUM TIMESTAMP CORE_SOFT_RLIMIT HOSTNAME
journalctl -b -n 1 --output=export --output-fields=MESSAGE,COREDUMP COREDUMP_EXE="/usr/bin/test-dump" |
    /usr/lib/systemd/systemd-coredump --backtrace $$ 0 0 6 1679509994 12345 mymachine
# Wait a bit for the coredump to get processed
timeout 30 bash -c "while [[ \$(coredumpctl list -q --no-legend $$ | wc -l) -eq 0 ]]; do sleep 1; done"
coredumpctl info "$$"
coredumpctl info COREDUMP_HOSTNAME="mymachine"


(! coredumpctl --hello-world)
(! coredumpctl -n 0)
(! coredumpctl -n -1)
(! coredumpctl --file=/dev/null)
(! coredumpctl --since=0)
(! coredumpctl --until='')
(! coredumpctl --since=today --until=yesterday)
(! coredumpctl --directory=/ --root=/)
(! coredumpctl --json=foo)
(! coredumpctl -F foo -F bar)
(! coredumpctl list 0)
(! coredumpctl list -- -1)
(! coredumpctl list '')
(! coredumpctl info /../.~=)
(! coredumpctl info '')
(! coredumpctl dump --output=/dev/full "$CORE_TEST_BIN")
(! coredumpctl dump --output=/dev/null --output=/dev/null "$CORE_TEST_BIN")
(! coredumpctl debug --debugger=/bin/false)
(! coredumpctl debug --debugger=/bin/true --debugger-arguments='"')
