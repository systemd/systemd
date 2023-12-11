#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Rotation/flush test, see https://github.com/systemd/systemd/issues/19895
journalctl --relinquish-var
[[ "$(systemd-detect-virt -v)" == "qemu" ]] && ITERATIONS=10 || ITERATIONS=50
for ((i = 0; i < ITERATIONS; i++)); do
    dd if=/dev/urandom bs=1M count=1 | base64 | systemd-cat
done
journalctl --rotate
# Let's test varlinkctl a bit, i.e. implement the equivalent of 'journalctl --rotate' via varlinkctl
varlinkctl call /run/systemd/journal/io.systemd.journal io.systemd.Journal.Rotate '{}'
journalctl --flush
varlinkctl call /run/systemd/journal/io.systemd.journal io.systemd.Journal.FlushToVar '{}'
journalctl --sync
varlinkctl call /run/systemd/journal/io.systemd.journal io.systemd.Journal.Synchronize '{}'
journalctl --rotate --vacuum-size=8M

# Reset the ratelimit buckets for the subsequent tests below.
systemctl restart systemd-journald

# Test stdout stream
write_and_match() {
    local input="${1:?}"
    local expected="${2?}"
    local id
    shift 2

    id="$(systemd-id128 new)"
    echo -ne "$input" | systemd-cat -t "$id" "$@"
    journalctl --sync
    diff <(echo -ne "$expected") <(journalctl -b -o cat -t "$id")
}
# Skip empty lines
write_and_match "\n\n\n" "" --level-prefix false
write_and_match "<5>\n<6>\n<7>\n" "" --level-prefix true
# Remove trailing spaces
write_and_match "Trailing spaces \t \n" "Trailing spaces\n" --level-prefix false
write_and_match "<5>Trailing spaces \t \n" "Trailing spaces\n" --level-prefix true
# Don't remove leading spaces
write_and_match " \t Leading spaces\n" " \t Leading spaces\n" --level-prefix false
write_and_match "<5> \t Leading spaces\n" " \t Leading spaces\n" --level-prefix true

# --output-fields restricts output
ID="$(systemd-id128 new)"
echo -ne "foo" | systemd-cat -t "$ID" --level-prefix false
# Let's test varlinkctl a bit, i.e. implement the equivalent of 'journalctl --sync' via varlinkctl
varlinkctl call /run/systemd/journal/io.systemd.journal io.systemd.Journal.Synchronize '{}'
journalctl -b -o export --output-fields=MESSAGE,FOO --output-fields=PRIORITY,MESSAGE -t "$ID" >/tmp/output
[[ $(wc -l </tmp/output) -eq 9 ]]
grep -q '^__CURSOR=' /tmp/output
grep -q '^MESSAGE=foo$' /tmp/output
grep -q '^PRIORITY=6$' /tmp/output
(! grep '^FOO=' /tmp/output)
(! grep '^SYSLOG_FACILITY=' /tmp/output)

# --truncate shows only first line, skip under asan due to logger
ID="$(systemd-id128 new)"
echo -e 'HEAD\nTAIL\nTAIL' | systemd-cat -t "$ID"
journalctl --sync
journalctl -b -t "$ID" | grep -q HEAD
journalctl -b -t "$ID" | grep -q TAIL
journalctl -b -t "$ID" --truncate-newline | grep -q HEAD
journalctl -b -t "$ID" --truncate-newline | grep -q -v TAIL

# '-b all' negates earlier use of -b (-b and -m are otherwise exclusive)
journalctl -b -1 -b all -m >/dev/null

# -b always behaves like -b0
journalctl -q -b-1 -b0 | head -1 >/tmp/expected
journalctl -q -b-1 -b | head -1 >/tmp/output
diff /tmp/expected /tmp/output
# ... even when another option follows (both of these should fail due to -m)
{ journalctl -ball -b0 -m 2>&1 || :; } | head -1 >/tmp/expected
{ journalctl -ball -b  -m 2>&1 || :; } | head -1 >/tmp/output
diff /tmp/expected /tmp/output

# https://github.com/systemd/systemd/issues/13708
ID=$(systemd-id128 new)
systemd-cat -t "$ID" bash -c 'echo parent; (echo child) & wait' &
PID=$!
wait $PID
journalctl --sync
# We can drop this grep when https://github.com/systemd/systemd/issues/13937
# has a fix.
journalctl -b -o export -t "$ID" --output-fields=_PID | grep '^_PID=' >/tmp/output
[[ $(wc -l </tmp/output) -eq 2 ]]
grep -q "^_PID=$PID" /tmp/output
grep -vq "^_PID=$PID" /tmp/output

# https://github.com/systemd/systemd/issues/15654
ID=$(systemd-id128 new)
printf "This will\nusually fail\nand be truncated\n" >/tmp/expected
systemd-cat -t "$ID" /bin/sh -c 'env echo -n "This will";echo;env echo -n "usually fail";echo;env echo -n "and be truncated";echo;'
journalctl --sync
journalctl -b -o cat -t "$ID" >/tmp/output
diff /tmp/expected /tmp/output
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_TRANSPORT | grep -Pc "^stdout$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_LINE_BREAK | grep -Pc "^pid-change$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_PID | sort -u | grep -c "^.*$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=MESSAGE | grep -Pc "^(This will|usually fail|and be truncated)$") -eq 3 ]]

# test that LogLevelMax can also suppress logging about services, not only by services
systemctl start silent-success
journalctl --sync
[[ -z "$(journalctl -b -q -u silent-success.service)" ]]

# Test syslog identifiers exclusion
systemctl start verbose-success
journalctl --sync
[[ -n "$(journalctl -b -q -u verbose-success.service -t systemd)" ]]
[[ -n "$(journalctl -b -q -u verbose-success.service -t echo)" ]]
[[ -n "$(journalctl -b -q -u verbose-success.service -T systemd)" ]]
[[ -n "$(journalctl -b -q -u verbose-success.service -T echo)" ]]
[[ -z "$(journalctl -b -q -u verbose-success.service -T echo -T systemd)" ]]

# Exercise the matching machinery
SYSTEMD_LOG_LEVEL=debug journalctl -b -n 1 /dev/null /dev/zero /dev/null /dev/null /dev/null
journalctl -b -n 1 /bin/true /bin/false
journalctl -b -n 1 /bin/true + /bin/false
journalctl -b -n 1 -r --unit "systemd*"

systemd-run --user -M "testuser@.host" /bin/echo hello
journalctl --sync
journalctl -b -n 1 -r --user-unit "*"

(! journalctl -b /dev/lets-hope-this-doesnt-exist)
(! journalctl -b /dev/null /dev/zero /dev/this-also-shouldnt-exist)
(! journalctl -b --unit "this-unit-should-not-exist*")

# Facilities & priorities
journalctl --facility help
journalctl --facility kern -n 1
journalctl --facility syslog --priority 0..3 -n 1
journalctl --facility syslog --priority 3..0 -n 1
journalctl --facility user --priority 0..0 -n 1
journalctl --facility daemon --priority warning -n 1
journalctl --facility daemon --priority warning..info -n 1
journalctl --facility daemon --priority notice..crit -n 1
journalctl --facility daemon --priority 5..crit -n 1

# Assorted combinations
journalctl -o help
journalctl -q -n all -a | grep . >/dev/null
journalctl -q --no-full | grep . >/dev/null
journalctl -q --user --system | grep . >/dev/null
journalctl --namespace "*" | grep . >/dev/null
journalctl --namespace "" | grep . >/dev/null
journalctl -q --namespace "+foo-bar-baz-$RANDOM" | grep . >/dev/null
(! journalctl -q --namespace "foo-bar-baz-$RANDOM" | grep .)
journalctl --root / | grep . >/dev/null
journalctl --cursor "t=0;t=-1;t=0;t=0x0" | grep . >/dev/null
journalctl --header | grep system.journal
journalctl --field _EXE | grep . >/dev/null
journalctl --no-hostname --utc --catalog | grep . >/dev/null
# Exercise executable_is_script() and the related code, e.g. `journalctl -b /path/to/a/script.sh` should turn
# into ((_EXE=/bin/bash AND _COMM=script.sh) AND _BOOT_ID=c002e3683ba14fa8b6c1e12878386514)
journalctl -b "$(readlink -f "$0")" | grep . >/dev/null
journalctl -b "$(systemd-id128 boot-id)" | grep . >/dev/null
journalctl --since yesterday --reverse | grep . >/dev/null
journalctl --machine .host | grep . >/dev/null
# Log something that journald will forward to wall
echo "Oh no!" | systemd-cat -t "emerg$RANDOM" -p emerg --stderr-priority emerg

TAG="$(systemd-id128 new)"
echo "Foo Bar Baz" | systemd-cat -t "$TAG"
journalctl --sync
# Relevant excerpt from journalctl(1):
#   If the pattern is all lowercase, matching is case insensitive. Otherwise, matching is case sensitive.
#   This can be overridden with the --case-sensitive option
journalctl -e -t "$TAG" --grep "Foo Bar Baz"
journalctl -e -t "$TAG" --grep "foo bar baz"
(! journalctl -e -t "$TAG" --grep "foo Bar baz")
journalctl -e -t "$TAG" --case-sensitive=false --grep "foo Bar baz"

(! journalctl --facility hopefully-an-unknown-facility)
(! journalctl --priority hello-world)
(! journalctl --priority 0..128)
(! journalctl --priority 0..systemd)

# Other options
journalctl --disk-usage
journalctl --dmesg -n 1
journalctl --fields
journalctl --list-boots
journalctl --update-catalog
journalctl --list-catalog

# Add new tests before here, the journald restarts below
# may make tests flappy.

# Don't lose streams on restart
systemctl start forever-print-hola
sleep 3
systemctl restart systemd-journald
sleep 3
systemctl stop forever-print-hola
[[ ! -f "/tmp/i-lose-my-logs" ]]

# https://github.com/systemd/systemd/issues/4408
rm -f /tmp/i-lose-my-logs
systemctl start forever-print-hola
sleep 3
systemctl kill --signal=SIGKILL systemd-journald
sleep 3
[[ ! -f "/tmp/i-lose-my-logs" ]]
systemctl stop forever-print-hola

set +o pipefail
# https://github.com/systemd/systemd/issues/15528
journalctl --follow --file=/var/log/journal/*/* | head -n1 | grep .
# https://github.com/systemd/systemd/issues/24565
journalctl --follow --merge | head -n1 | grep .
set -o pipefail

# https://github.com/systemd/systemd/issues/26746
rm -f /tmp/issue-26746-log /tmp/issue-26746-cursor
ID="$(systemd-id128 new)"
journalctl -t "$ID" --follow --cursor-file=/tmp/issue-26746-cursor | tee /tmp/issue-26746-log &
systemd-cat -t "$ID" /bin/sh -c 'echo hogehoge'
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ -f /tmp/issue-26746-log && "$(cat /tmp/issue-26746-log)" =~ hogehoge ]]; do sleep .5; done'
pkill -TERM journalctl
timeout 10 bash -c 'until test -f /tmp/issue-26746-cursor; do sleep .5; done'
CURSOR_FROM_FILE="$(cat /tmp/issue-26746-cursor)"
CURSOR_FROM_JOURNAL="$(journalctl -t "$ID" --output=export MESSAGE=hogehoge | sed -n -e '/__CURSOR=/ { s/__CURSOR=//; p }')"
test "$CURSOR_FROM_FILE" = "$CURSOR_FROM_JOURNAL"

# Check that the seqnum field at least superficially works
systemd-cat echo "ya"
journalctl --sync
SEQNUM1=$(journalctl -o export -n 1 | grep -Ea "^__SEQNUM=" | cut -d= -f2)
systemd-cat echo "yo"
journalctl --sync
SEQNUM2=$(journalctl -o export -n 1 | grep -Ea "^__SEQNUM=" | cut -d= -f2)
test "$SEQNUM2" -gt "$SEQNUM1"

# Test for journals without RTC
# See: https://github.com/systemd/systemd/issues/662
JOURNAL_DIR="$(mktemp -d)"
while read -r file; do
    filename="${file##*/}"
    unzstd "$file" -o "$JOURNAL_DIR/${filename%*.zst}"
done < <(find /test-journals/no-rtc -name "*.zst")

journalctl --directory="$JOURNAL_DIR" --list-boots --output=json >/tmp/lb1
diff -u /tmp/lb1 - <<'EOF'
[{"index":-3,"boot_id":"5ea5fc4f82a14186b5332a788ef9435e","first_entry":1666569600994371,"last_entry":1666584266223608},{"index":-2,"boot_id":"bea6864f21ad4c9594c04a99d89948b0","first_entry":1666569601005945,"last_entry":1666584347230411},{"index":-1,"boot_id":"4c708e1fd0744336be16f3931aa861fb","first_entry":1666569601017222,"last_entry":1666584354649355},{"index":0,"boot_id":"35e8501129134edd9df5267c49f744a4","first_entry":1666569601009823,"last_entry":1666584438086856}]
EOF
rm -rf "$JOURNAL_DIR" /tmp/lb1

# Check that using --after-cursor/--cursor-file= together with journal filters doesn't
# skip over entries matched by the filter
# See: https://github.com/systemd/systemd/issues/30288
UNIT_NAME="test-cursor-$RANDOM.service"
CURSOR_FILE="$(mktemp)"
# Generate some messages we can match against
journalctl --cursor-file="$CURSOR_FILE" -n1
systemd-run --unit="$UNIT_NAME" --wait --service-type=exec bash -xec "echo hello; echo world"
journalctl --sync
# --after-cursor= + --unit=
# The format of the "Starting ..." message depends on StatusUnitFormat=, so match only the beginning
# which should be enough in this case
[[ "$(journalctl -n 1 -p info -o cat --unit="$UNIT_NAME" --after-cursor="$(<"$CURSOR_FILE")" _PID=1 )" =~ ^Starting\  ]]
# There should be no such messages before the cursor
[[ -z "$(journalctl -n 1 -p info -o cat --unit="$UNIT_NAME" --after-cursor="$(<"$CURSOR_FILE")" --reverse)" ]]
# --cursor-file= + a journal filter
diff <(journalctl --cursor-file="$CURSOR_FILE" -p info -o cat _SYSTEMD_UNIT="$UNIT_NAME") - <<EOF
+ echo hello
hello
+ echo world
world
EOF
rm -f "$CURSOR_FILE"
