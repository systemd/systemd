#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if systemd-detect-virt -cq; then
    echo "This test requires a VM, skipping the test"
    exit 0
fi

# shellcheck disable=SC2317
at_exit() {
    local EC=$?

    if [[ $EC -ne 0 ]] && [[ -e /tmp/console.dump ]]; then
        cat /tmp/console.dump
    fi

    if mountpoint -q /var/log/journal; then
        journalctl --relinquish-var
        umount /var/log/journal
        journalctl --flush
    fi

    return 0
}

vcs_dump_and_check() {
    local expected_message="${1:?}"

    # It might take a while before the systemd-bsod stuff appears on the VCS,
    # so try it a couple of times
    for _ in {0..9}; do
        setterm --term linux --dump --file /tmp/console.dump
        if grep -aq "Press any key to exit" /tmp/console.dump &&
           grep -aq "$expected_message" /tmp/console.dump &&
           grep -aq "The current boot has failed" /tmp/console.dump; then

            return 0
        fi

        sleep .5
    done

    return 1
}

# Since systemd-bsod always fetches only the first emergency message from the
# current boot, let's temporarily overmount /var/log/journal with a tmpfs,
# as we're going to wipe it multiple times, but we need to keep the original
# journal intact for the other tests to work correctly.
trap at_exit EXIT
mount -t tmpfs tmpfs /var/log/journal
systemctl restart systemd-journald

systemctl stop systemd-bsod

# Since we just wiped the journal, there should be no emergency messages and
# systemd-bsod should be just a no-op
timeout 10s /usr/lib/systemd/systemd-bsod
setterm --term linux --dump --file /tmp/console.dump
(! grep "The current boot has failed" /tmp/console.dump)

# systemd-bsod should pick up emergency messages only with UID=0, so let's check
# that as well
systemd-run --user --machine testuser@ --wait --pipe systemd-cat -p emerg echo "User emergency message"
systemd-cat -p emerg echo "Root emergency message"
journalctl --sync
# Set $SYSTEMD_COLORS so systemd-bsod also prints out the QR code
SYSTEMD_COLORS=256 /usr/lib/systemd/systemd-bsod &
PID=$!
vcs_dump_and_check "Root emergency message"
grep -aq "Scan the QR code" /tmp/console.dump
# TODO: check if systemd-bsod exits on a key press (didn't figure this one out yet)
kill $PID
timeout 10 bash -c "while kill -0 $PID; do sleep .5; done"

# Wipe the journal
journalctl --vacuum-size=1 --rotate
(! journalctl -q -b -p emerg --grep .)

# Check the systemd-bsod.service as well
# Note: the systemd-bsod.service unit has ConditionVirtualization=no, so let's
# temporarily override it just for the test
mkdir /run/systemd/system/systemd-bsod.service.d
printf '[Unit]\nConditionVirtualization=\n' >/run/systemd/system/systemd-bsod.service.d/99-override.conf
systemctl daemon-reload
systemctl start systemd-bsod
systemd-cat -p emerg echo "Service emergency message"
vcs_dump_and_check "Service emergency message"
systemctl stop systemd-bsod

# Wipe the journal
journalctl --vacuum-size=1 --rotate
(! journalctl -q -b -p emerg --grep .)

# Same as above, but make sure the service responds to signals even when there are
# no "emerg" messages, see systemd/systemd#30084
(! systemctl is-active systemd-bsod)
systemctl start systemd-bsod
timeout 5s bash -xec 'until systemctl is-active systemd-bsod; do sleep .5; done'
timeout 5s systemctl stop systemd-bsod
timeout 5s bash -xec 'while systemctl is-active systemd-bsod; do sleep .5; done'
