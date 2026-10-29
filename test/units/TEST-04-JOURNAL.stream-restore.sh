#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that stdout streams are restored from the right state file on journald restart: state files include
# the socket cookie, state files named without it by older versions are still used and renamed, and state
# files of other streams with the same inode number are not used.

STREAMS=/run/systemd/journal/streams

start_logger() {
    local id="${1:?}"

    systemd-run --unit="$id.service" -p SyslogIdentifier="$id" \
                bash -c "i=0; while :; do echo \"$id \$((i++))\"; sleep .2; done"
}

# Print the state file of the stream with the given identifier, once PID 1 has the stream in its fd store
state_file_of() {
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
    systemctl stop stream-restore-cookie.service \
                   stream-restore-legacy.service \
                   stream-restore-both.service \
                   stream-restore-other.service || :
}

trap at_exit EXIT

# State files include the socket cookie, and the stream is restored from them with its identifier
start_logger stream-restore-cookie
F="$(state_file_of stream-restore-cookie)"
[[ "$(basename "$F")" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]]
restart_and_wait_for_logs -t stream-restore-cookie
[[ -e "$F" ]]
systemctl stop stream-restore-cookie.service

# A state file named without cookie is used, and renamed to include the cookie
start_logger stream-restore-legacy
F="$(state_file_of stream-restore-legacy)"
mv "$F" "${F%:*}"
restart_and_wait_for_logs -t stream-restore-legacy
[[ ! -e "${F%:*}" ]]
grep -x IDENTIFIER=stream-restore-legacy "$F"
systemctl stop stream-restore-legacy.service

# A state file with and one without cookie for the same stream: the one with cookie is used, the other one
# is removed
start_logger stream-restore-both
F="$(state_file_of stream-restore-both)"
sed 's/^IDENTIFIER=.*/IDENTIFIER=stream-restore-both-bogus/' "$F" >"${F%:*}"
restart_and_wait_for_logs -t stream-restore-both
[[ ! -e "${F%:*}" ]]
[[ -e "$F" ]]
[[ -z "$(journalctl -q -t stream-restore-both-bogus)" ]]
systemctl stop stream-restore-both.service

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
