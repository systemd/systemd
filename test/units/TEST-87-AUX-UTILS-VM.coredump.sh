#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ -L $(command -v sleep) ]]; then
    # coreutils is built with --enable-single-binary=symlinks, and we cannot rename it.
    exit 0
fi

# Make sure the binary name fits into 15 characters
CORE_TEST_BIN="/tmp/test-dump"
CORE_TEST_UNPRIV_BIN="/tmp/test-usr-dump"
MAKE_DUMP_SCRIPT="/tmp/make-dump"
# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

at_exit() {
    rm -fv -- "$CORE_TEST_BIN" "$CORE_TEST_UNPRIV_BIN" "$MAKE_DUMP_SCRIPT"
}

(! systemd-detect-virt -cq)

trap at_exit EXIT

# Sync and rotate journal to make all coredump entries stored in system.journal.
journalctl --sync
journalctl --rotate

# Check that we're the ones to receive coredumps
sysctl kernel.core_pattern | grep systemd-coredump

# Prepare "fake" binaries for coredumps, so we can properly exercise
# the matching stuff too
cp -vf /bin/sleep "${CORE_TEST_BIN:?}"
cp -vf /bin/sleep "${CORE_TEST_UNPRIV_BIN:?}"
# Simple script that spawns given "fake" binary and then kills it with
# given signal
cat >"${MAKE_DUMP_SCRIPT:?}" <<\EOF
#!/usr/bin/env bash
set -ex

bin="${1:?}"
sig="${2:?}"

ulimit -c unlimited
"$bin" infinity &
pid=$!
# Sync with the "fake" binary, so we kill it once it's fully forked off,
# otherwise we might kill it during fork and kernel would then report
# "wrong" binary name (i.e. $MAKE_DUMP_SCRIPT instead of $CORE_TEST_BIN).
# In this case, wait until the "fake" binary (sleep in this case) enters
# the "interruptible sleep" state, at which point it should be ready
# to be sacrificed.
for _ in {0..9}; do
    read -ra self_stat <"/proc/$pid/stat"
    [[ "${self_stat[2]}" == S ]] && break
    sleep .5
done
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

if cgroupfs_supports_user_xattrs; then
    # Make sure we can forward crashes back to containers
    CONTAINER="TEST-87-AUX-UTILS-VM-container"

    mkdir -p "/var/lib/machines/$CONTAINER"
    mkdir -p "/run/systemd/system/systemd-nspawn@$CONTAINER.service.d"
    # Bind-mounting /etc into the container kinda defeats the purpose of --volatile=,
    # but we need the ASan-related overrides scattered across /etc
    cat > "/run/systemd/system/systemd-nspawn@$CONTAINER.service.d/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=systemd-nspawn --quiet --link-journal=try-guest --keep-unit --machine=%i --boot \
                         --volatile=yes --directory=/ --bind-ro=/etc --inaccessible=/etc/machine-id
EOF
    systemctl daemon-reload

    [[ "$(systemd-detect-virt)" == "qemu" ]] && TIMEOUT=120 || TIMEOUT=60

    machinectl start "$CONTAINER"
    timeout "$TIMEOUT" bash -xec "until systemd-run -M '$CONTAINER' -q --wait --pipe true; do sleep .5; done"

    [[ "$(systemd-run -M "$CONTAINER" -q --wait --pipe coredumpctl list -q --no-legend sleep | wc -l)" -eq 0 ]]
    machinectl copy-to "$CONTAINER" "$MAKE_DUMP_SCRIPT"
    systemd-run -M "$CONTAINER" -q --wait --pipe "$MAKE_DUMP_SCRIPT" "sleep" "SIGABRT"
    systemd-run -M "$CONTAINER" -q --wait --pipe "$MAKE_DUMP_SCRIPT" "sleep" "SIGTRAP"
    # Wait a bit for the coredumps to get processed
    timeout 30 bash -c "while [[ \$(systemd-run -M $CONTAINER -q --wait --pipe coredumpctl list -q --no-legend sleep | wc -l) -lt 2 ]]; do sleep 1; done"

    machinectl stop "$CONTAINER"
    rm -rf "/var/lib/machines/$CONTAINER"
    unset CONTAINER
fi

# Sync and rotate journals (again) to make coredumps stored in archived journal. Otherwise, the main active
# journal file may be already mostly filled with the coredumps, and may trigger rotation during the sanity
# checks below. If coredumpctl accesses the main journal currently rotationg, then it warns the following and
# skips reading the main journal, and cannot find the recent coredumps:
# TEST-87-AUX-UTILS-VM.sh[839]: + coredumpctl -n 1
# TEST-87-AUX-UTILS-VM.sh[1172]: Journal file /var/log/journal/a8285330872602d1377cbaaf68869946/system.journal is truncated, ignoring file.
# TEST-87-AUX-UTILS-VM.sh[1172]: No coredumps found.
journalctl --sync
journalctl --rotate

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
coredumpctl --file="/var/log/journal/$(</etc/machine-id)"/*.journal
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
UNPRIV_CMD=(systemd-run --user --wait --pipe -M "testuser@.host" -E SYSTEMD_PAGER --)
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

# Sync and rotate journal again to make the coredump stored in an archived journal.
journalctl --sync
journalctl --rotate

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
# Pass one of the existing journal coredump records to systemd-coredump.
# Use our PID as the source to be able to create a PIDFD and to make matching easier.
# systemd-coredump args: PID UID GID SIGNUM TIMESTAMP CORE_SOFT_RLIMIT [HOSTNAME]
journalctl -b -n 1 --output=export --output-fields=MESSAGE,COREDUMP COREDUMP_EXE="/usr/bin/test-dump" |
    /usr/lib/systemd/systemd-coredump --backtrace $$ 0 0 6 1679509900 12345
journalctl -b -n 1 --output=export --output-fields=MESSAGE,COREDUMP COREDUMP_EXE="/usr/bin/test-dump" |
    /usr/lib/systemd/systemd-coredump --backtrace $$ 0 0 6 1679509901 12345 mymachine
journalctl -b -n 1 --output=export --output-fields=MESSAGE,COREDUMP COREDUMP_EXE="/usr/bin/test-dump" |
    /usr/lib/systemd/systemd-coredump --backtrace $$ 0 0 6 1679509902 12345 youmachine 1
# Wait a bit for the coredumps to get processed
timeout 30 bash -c "while [[ \$(coredumpctl list -q --no-legend $$ | wc -l) -lt 3 ]]; do sleep 1; done"
coredumpctl info $$
coredumpctl info COREDUMP_TIMESTAMP=1679509900000000
coredumpctl info COREDUMP_TIMESTAMP=1679509901000000
coredumpctl info COREDUMP_HOSTNAME="mymachine"
coredumpctl info COREDUMP_TIMESTAMP=1679509902000000
coredumpctl info COREDUMP_HOSTNAME="youmachine"
coredumpctl info COREDUMP_DUMPABLE="1"

# This used to cause a stack overflow
systemd-run -t --property CoredumpFilter=all ls /tmp
systemd-run -t --property CoredumpFilter=default ls /tmp

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

# Test for EnterNamespace= feature
#
# dwfl_set_sysroot() is supported only in libdw-0.192 or newer.
#
# FIXME: drop the objdump call once https://github.com/systemd/systemd/pull/39268#issuecomment-3390745718 is
#        addressed
if pkgconf --atleast-version 0.192 libdw &&
    objdump -h -j .gnu_debugdata -j .debug_info /usr/lib/systemd/tests/unit-tests/manual/test-coredump-stacktrace; then
    MAKE_STACKTRACE_DUMP="/tmp/make-stacktrace-dump"

    # Simple script that mounts tmpfs on /tmp/ and copies the crashing test binary there, which in
    # combination with `unshare --mount` ensures the "outside" systemd-coredump process won't be able to
    # access the crashed binary (and hence won't be able to symbolize its stacktrace) unless
    # EnterNamespace=yes is used
    cat >"$MAKE_STACKTRACE_DUMP" <<\EOF
#!/usr/bin/bash -eux

TARGET="/tmp/${1:?}"
EC=0

# "Unhide" debuginfo in the namespace (see the comment below)
test -d /usr/lib/debug/ && umount /usr/lib/debug/

mount -t tmpfs tmpfs /tmp/
cp /usr/lib/systemd/tests/unit-tests/manual/test-coredump-stacktrace "$TARGET"

$TARGET || EC=$?
if [[ $EC -ne 139 ]]; then
    echo >&2 "$TARGET didn't crash, this shouldn't happen"
    exit 1
fi

exit 0
EOF
    chmod +x "$MAKE_STACKTRACE_DUMP"

    # Since the test-coredump-stacktrace binary is built together with rest of the systemd its debug symbols
    # might be part of debuginfo packages (if supported & built), and libdw will then use them to symbolize
    # the stacktrace even if it doesn't have access to the original crashing binary. Let's make the test
    # simpler and just "hide" the debuginfo data, so libdw is forced to access the target namespace to get
    # the necessary symbols
    test -d /usr/lib/debug/ && mount -t tmpfs tmpfs /usr/lib/debug/

    mkdir -p /run/systemd/coredump.conf.d/
    printf '[Coredump]\nEnterNamespace=no' >/run/systemd/coredump.conf.d/99-enter-namespace.conf

    unshare --pid --fork --mount-proc --mount --uts --ipc --net "$MAKE_STACKTRACE_DUMP" "test-stacktrace-not-symbolized"
    timeout 30 bash -c "until coredumpctl list -q --no-legend /tmp/test-stacktrace-not-symbolized; do sleep .2; done"
    coredumpctl info /tmp/test-stacktrace-not-symbolized | tee /tmp/not-symbolized.log
    (! grep -E "#[0-9]+ .* main " /tmp/not-symbolized.log)
    (! grep -E "#[0-9]+ .* foo " /tmp/not-symbolized.log)
    (! grep -E "#[0-9]+ .* bar " /tmp/not-symbolized.log)
    (! grep -E "#[0-9]+ .* baz " /tmp/not-symbolized.log)

    printf '[Coredump]\nEnterNamespace=yes' >/run/systemd/coredump.conf.d/99-enter-namespace.conf
    unshare --pid --fork --mount-proc --mount --uts --ipc --net "$MAKE_STACKTRACE_DUMP" "test-stacktrace-symbolized"
    timeout 30 bash -c "until coredumpctl list -q --no-legend /tmp/test-stacktrace-symbolized; do sleep .2; done"
    coredumpctl info /tmp/test-stacktrace-symbolized | tee /tmp/symbolized.log
    grep -E "#[0-9]+ .* main " /tmp/symbolized.log
    grep -E "#[0-9]+ .* foo " /tmp/symbolized.log
    grep -E "#[0-9]+ .* bar " /tmp/symbolized.log
    grep -E "#[0-9]+ .* baz " /tmp/symbolized.log

    test -d /usr/lib/debug/ && umount /usr/lib/debug/
    rm -f "$MAKE_STACKTRACE_DUMP" /run/systemd/coredump.conf.d/99-enter-namespace.conf /tmp/{not-,}symbolized.log
else
    echo "libdw doesn't not support setting sysroot, skipping EnterNamespace= test"
fi
