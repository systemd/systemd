#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that stdout streams are restored from the right state file on journald restart: state files include
# the socket cookie, state files named without it by older versions are still used, and state files of other
# streams with the same inode number, with or without cookie, are not used. A stream that can't be restored
# is shut down, unless the state files couldn't be read.

STREAMS=/run/systemd/journal/streams

start_logger() {
    local id="${1:?}"

    # Stop once a write fails, so that a stream that is shut down ends the service
    systemd-run --unit="$id.service" -p SyslogIdentifier="$id" \
                bash -c "i=0; while echo \"$id \$((i++))\"; do sleep .2; done"
}

# Print the state file of the stream with the given identifier, once PID 1 has the stream in its fd store
state_file_of() {
    # Called in command substitution ("$(state_file_of ...)"), where errexit is not inherited
    # (no inherit_errexit), so re-enable it to make the assertions below actually abort.
    set -e

    local id="${1:?}"
    local f ino

    f="$(timeout 30 bash -c "until grep -lx 'IDENTIFIER=$id' $STREAMS/* 2>/dev/null; do sleep .2; done")"
    [[ "$(wc -l <<<"$f")" -eq 1 ]]

    ino="$(basename "$f" | cut -d: -f2)"
    for _ in {1..150}; do
        if find /proc/1/fd -lname "socket:\[$ino\]" | grep . >/dev/null; then
            echo "$f"
            return 0
        fi
        sleep .2
    done

    return 1
}

# Restart journald and wait until new lines matching the given journalctl arguments are logged
restart_and_wait_for_logs() {
    local cursor

    # Reset the start-limit counters, as we're going to restart journald a couple of times
    systemctl reset-failed systemd-journald.service
    systemctl restart systemd-journald
    journalctl --sync
    cursor="$(journalctl -q "$@" -n 1 -o export | sed -n 's/^__CURSOR=//p')"
    [[ -n "$cursor" ]]

    for _ in {1..150}; do
        journalctl --sync
        if journalctl -q "$@" --after-cursor="$cursor" | grep .; then
            return 0
        fi
        sleep .2
    done

    return 1
}

at_exit() {
    # Put the state files back if we failed while they were moved away, and let journald restore the
    # streams from them
    if [[ -e "$STREAMS.saved" ]]; then
        rm -f "$STREAMS" || :
        mv -T "$STREAMS.saved" "$STREAMS" || :
        systemctl reset-failed systemd-journald.service || :
        systemctl restart systemd-journald || :
    fi

    systemctl stop stream-restore-cookie.service \
                   stream-restore-legacy.service \
                   stream-restore-other.service \
                   stream-restore-legacy-other.service \
                   stream-restore-lost.service \
                   stream-restore-unreadable.service || :
    systemctl reset-failed systemd-journald.service || :
}

trap at_exit EXIT

# State files include the socket cookie, and the stream is restored from them with its identifier
start_logger stream-restore-cookie
F="$(state_file_of stream-restore-cookie)"
[[ "$(basename "$F")" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]]
restart_and_wait_for_logs -t stream-restore-cookie
[[ -e "$F" ]]
systemctl stop stream-restore-cookie.service

# A state file named without cookie, as written by older versions, is used and left as it is
start_logger stream-restore-legacy
F="$(state_file_of stream-restore-legacy)"
mv "$F" "${F%:*}"
restart_and_wait_for_logs -t stream-restore-legacy
grep -x IDENTIFIER=stream-restore-legacy "${F%:*}"
[[ ! -e "$F" ]]
systemctl stop stream-restore-legacy.service

# A state file with the same inode number but another cookie, i.e. of another stream after the inode number
# was reused, is not used for the stream and removed
start_logger stream-restore-other
F="$(state_file_of stream-restore-other)"
sed 's/^IDENTIFIER=.*/IDENTIFIER=stream-restore-other-bogus/' "$F" >"${F%:*}:1"
restart_and_wait_for_logs -t stream-restore-other
[[ ! -e "${F%:*}:1" ]]
[[ -e "$F" ]]
[[ -z "$(journalctl -q -t stream-restore-other-bogus)" ]]
systemctl stop stream-restore-other.service

# A state file without cookie with the same inode number, e.g. of a stream from before the upgrade, does not
# take the fd of a stream that has a state file with cookie, and is removed
start_logger stream-restore-legacy-other
F="$(state_file_of stream-restore-legacy-other)"
sed 's/^IDENTIFIER=.*/IDENTIFIER=stream-restore-legacy-other-bogus/' "$F" >"${F%:*}"
restart_and_wait_for_logs -t stream-restore-legacy-other
[[ ! -e "${F%:*}" ]]
[[ -e "$F" ]]
[[ -z "$(journalctl -q -t stream-restore-legacy-other-bogus)" ]]
systemctl stop stream-restore-legacy-other.service

# A stream whose state file is gone can't be restored, and is shut down: otherwise PID 1 would keep it open
# in the fd store with nothing reading from it, and the writer would block forever once its buffer is full
start_logger stream-restore-lost
F="$(state_file_of stream-restore-lost)"
INO="$(basename "$F" | cut -d: -f2)"
rm "$F"
systemctl reset-failed systemd-journald.service
systemctl restart systemd-journald
# The writer gets EPIPE, which ends the loop
timeout 30 bash -c 'while systemctl is-active -q stream-restore-lost.service; do sleep .2; done'
[[ -z "$(find /proc/1/fd -lname "socket:\[$INO\]")" ]]

# If the state files can't be read, streams are not shut down, as they might still have a state file: here
# they do, and the next restart restores them
start_logger stream-restore-unreadable
state_file_of stream-restore-unreadable >/dev/null
mv "$STREAMS" "$STREAMS.saved"
touch "$STREAMS"
systemctl reset-failed systemd-journald.service
systemctl restart systemd-journald
rm "$STREAMS"
mv -T "$STREAMS.saved" "$STREAMS"
restart_and_wait_for_logs -t stream-restore-unreadable
systemctl is-active stream-restore-unreadable.service
systemctl stop stream-restore-unreadable.service
