#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Limit the maximum journal size
trap "journalctl --rotate --vacuum-size=16M" EXIT

# Rotation/flush test, see https://github.com/systemd/systemd/issues/19895
journalctl --relinquish-var
[[ "$(systemd-detect-virt -v)" == "qemu" ]] && ITERATIONS=10 || ITERATIONS=50
for ((i = 0; i < ITERATIONS; i++)); do
    dd if=/dev/urandom bs=1M count=1 | base64 | systemd-cat
done
journalctl --rotate
journalctl --flush
journalctl --sync
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
journalctl --sync
journalctl -b -o export --output-fields=MESSAGE,FOO --output-fields=PRIORITY,MESSAGE -t "$ID" >/tmp/output
[[ $(wc -l </tmp/output) -eq 9 ]]
grep -q '^__CURSOR=' /tmp/output
grep -q '^MESSAGE=foo$' /tmp/output
grep -q '^PRIORITY=6$' /tmp/output
(! grep '^FOO=' /tmp/output)
(! grep '^SYSLOG_FACILITY=' /tmp/output)

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
ID=$(systemd-id128 new)
journalctl -t "$ID" --follow --cursor-file=/tmp/issue-26746-cursor | tee /tmp/issue-26746-log &
systemd-cat -t "$ID" /bin/sh -c 'echo hogehoge'
# shellcheck disable=SC2016
timeout 10 bash -c 'while ! [[ -f /tmp/issue-26746-log && "$(cat /tmp/issue-26746-log)" =~ hogehoge ]]; do sleep .5; done'
pkill -TERM journalctl
test -f /tmp/issue-26746-cursor
CURSOR_FROM_FILE=$(cat /tmp/issue-26746-cursor)
CURSOR_FROM_JOURNAL=$(journalctl -t "$ID" --output export MESSAGE=hogehoge | sed -n -e '/__CURSOR=/ { s/__CURSOR=//; p }')
test "$CURSOR_FROM_FILE" = "$CURSOR_FROM_JOURNAL"

add_logs_filtering_override() {
    local unit="${1:?}"
    local override_name="${2:?}"
    local log_filter="${3:-}"

    mkdir -p "/run/systemd/system/$unit.d/"
    echo -ne "[Service]\nLogFilterPatterns=$log_filter" >"/run/systemd/system/$unit.d/$override_name.conf"
    systemctl daemon-reload
}

run_service_and_fetch_logs() {
    local unit="${1:?}"
    local start end

    start="$(date '+%Y-%m-%d %T.%6N')"
    systemctl restart "$unit"
    sleep .5
    journalctl --sync
    end="$(date '+%Y-%m-%d %T.%6N')"

    journalctl -q -u "$unit" -S "$start" -U "$end" -p notice
    systemctl stop "$unit"
}

is_xattr_supported() {
    local start end

    start="$(date '+%Y-%m-%d %T.%6N')"
    systemd-run --unit text_xattr --property LogFilterPatterns=log sh -c "sleep .5"
    sleep .5
    journalctl --sync
    end="$(date '+%Y-%m-%d %T.%6N')"
    systemctl stop text_xattr

    ! journalctl -q -u "text_xattr" -S "$start" -U "$end" --grep "Failed to set 'user.journald_log_filter_patterns' xattr.*not supported$"
}

if is_xattr_supported; then
    # Accept all log messages
    add_logs_filtering_override "logs-filtering.service" "00-reset" ""
    [[ -n $(run_service_and_fetch_logs "logs-filtering.service") ]]

    add_logs_filtering_override "logs-filtering.service" "01-allow-all" ".*"
    [[ -n $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Discard all log messages
    add_logs_filtering_override "logs-filtering.service" "02-discard-all" "~.*"
    [[ -z $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Accept all test messages
    add_logs_filtering_override "logs-filtering.service" "03-reset" ""
    [[ -n $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Discard all test messages
    add_logs_filtering_override "logs-filtering.service" "04-discard-gg" "~.*gg.*"
    [[ -z $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Deny filter takes precedence
    add_logs_filtering_override "logs-filtering.service" "05-allow-all-but-too-late" ".*"
    [[ -z $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Use tilde in a deny pattern
    add_logs_filtering_override "logs-filtering.service" "06-reset" ""
    add_logs_filtering_override "logs-filtering.service" "07-prevent-tilde" "~~more~"
    [[ -z $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Only allow a pattern that won't be matched
    add_logs_filtering_override "logs-filtering.service" "08-reset" ""
    add_logs_filtering_override "logs-filtering.service" "09-allow-only-non-existing" "non-existing string"
    [[ -z $(run_service_and_fetch_logs "logs-filtering.service") ]]

    # Allow a pattern starting with a tilde
    add_logs_filtering_override "logs-filtering.service" "10-allow-with-escape-char" "\\\\x7emore~"
    [[ -n $(run_service_and_fetch_logs "logs-filtering.service") ]]

    add_logs_filtering_override "delegated-cgroup-filtering.service" "00-allow-all" ".*"
    [[ -n $(run_service_and_fetch_logs "delegated-cgroup-filtering.service") ]]

    add_logs_filtering_override "delegated-cgroup-filtering.service" "01-discard-hello" "~hello"
    [[ -z $(run_service_and_fetch_logs "delegated-cgroup-filtering.service") ]]

    rm -rf /run/systemd/system/{logs-filtering,delegated-cgroup-filtering}.service.d
fi

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
[{"index":-3,"boot_id":"5ea5fc4f82a14186b5332a788ef9435e","first_entry":1666569600994371,"last_entry":1666584266223608},{"index":-2,"boot_id":"bea6864f21ad4c9594c04a99d89948b0","first_entry":1666584266731785,"last_entry":1666584347230411},{"index":-1,"boot_id":"4c708e1fd0744336be16f3931aa861fb","first_entry":1666584348378271,"last_entry":1666584354649355},{"index":0,"boot_id":"35e8501129134edd9df5267c49f744a4","first_entry":1666584356661527,"last_entry":1666584438086856}]
EOF
rm -rf "$JOURNAL_DIR" /tmp/lb1

# https://bugzilla.redhat.com/show_bug.cgi?id=2183546
mkdir /run/systemd/system/systemd-journald.service.d
MID=$(cat /etc/machine-id)
for c in "NONE" "XZ" "LZ4" "ZSTD"; do
    cat >/run/systemd/system/systemd-journald.service.d/compress.conf <<EOF
[Service]
Environment=SYSTEMD_JOURNAL_COMPRESS=${c}
EOF
    systemctl daemon-reload
    systemctl restart systemd-journald.service
    journalctl --rotate

    ID=$(systemd-id128 new)
    systemd-cat -t "$ID" /bin/bash -c "for ((i=0;i<100;i++)); do echo -n hoge with ${c}; done; echo"
    journalctl --sync
    timeout 10 bash -c "while ! SYSTEMD_LOG_LEVEL=debug journalctl --verify --quiet --file /var/log/journal/$MID/system.journal 2>&1 | grep -q -F 'compress=${c}'; do sleep .5; done"

    # $SYSTEMD_JOURNAL_COMPRESS= also works for journal-remote
    if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
        for cc in "NONE" "XZ" "LZ4" "ZSTD"; do
            rm -f /tmp/foo.journal
            SYSTEMD_JOURNAL_COMPRESS="${cc}" /usr/lib/systemd/systemd-journal-remote --split-mode=none -o /tmp/foo.journal --getter="journalctl -b -o export -t $ID"
            SYSTEMD_LOG_LEVEL=debug journalctl --verify --quiet --file /tmp/foo.journal 2>&1 | grep -q -F "compress=${cc}"
            journalctl -t "$ID" -o cat --file /tmp/foo.journal | grep -q -F "hoge with ${c}"
        done
    fi
done
rm /run/systemd/system/systemd-journald.service.d/compress.conf
systemctl daemon-reload
systemctl restart systemd-journald.service
journalctl --rotate

# Corrupted journals
JOURNAL_DIR="$(mktemp -d)"
REMOTE_OUT="$(mktemp -d)"
# tar on C8S doesn't support the --zstd option
unzstd --stdout "/test-journals/afl-corrupted-journals.tar.zst" | tar -xC "$JOURNAL_DIR/"
while read -r file; do
    filename="${file##*/}"
    unzstd "$file" -o "$JOURNAL_DIR/${filename%*.zst}"
done < <(find /test-journals/corrupted/ -name "*.zst")
# First, try each of them sequentially. Skip this part when running with plain
# QEMU, as it is excruciatingly slow
# Note: we care only about exit code 124 (timeout) and special bash exit codes
# >124 (like signals)
if [[ "$(systemd-detect-virt -v)" != "qemu" ]]; then
    while read -r file; do
        timeout 10 journalctl --file="$file" --boot >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --verify >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --output=export >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --fields >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --list-boots >/dev/null || [[ $? -lt 124 ]]
        if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
            timeout 10 /usr/lib/systemd/systemd-journal-remote \
                            --getter="journalctl --file=$file --output=export" \
                            --split-mode=none \
                            --output="$REMOTE_OUT/system.journal" || [[ $? -lt 124 ]]
            timeout 10 journalctl --directory="$REMOTE_OUT" >/dev/null || [[ $? -lt 124 ]]
            rm -f "$REMOTE_OUT"/*
        fi
    done < <(find "$JOURNAL_DIR" -type f)
fi
# And now all at once
timeout 30 journalctl --directory="$JOURNAL_DIR" --boot >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --verify >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --output=export >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --fields >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --list-boots >/dev/null || [[ $? -lt 124 ]]
if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
    timeout 30 /usr/lib/systemd/systemd-journal-remote \
                    --getter="journalctl --directory=$JOURNAL_DIR --output=export" \
                    --split-mode=none \
                    --output="$REMOTE_OUT/system.journal" || [[ $? -lt 124 ]]
    timeout 30 journalctl --directory="$REMOTE_OUT" >/dev/null || [[ $? -lt 124 ]]
    rm -f "$REMOTE_OUT"/*
fi

touch /testok
