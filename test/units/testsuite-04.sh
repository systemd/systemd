#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Limit the maximum journal size
trap "journalctl --rotate --vacuum-size=16M" EXIT

# Rotation/flush test, see https://github.com/systemd/systemd/issues/19895
journalctl --relinquish-var
for _ in {0..50}; do
    dd if=/dev/urandom bs=1M count=1 | base64 | systemd-cat
done
journalctl --rotate
journalctl --flush
journalctl --sync

# Reset the ratelimit buckets for the subsequent tests below.
systemctl restart systemd-journald

# Test stdout stream

# Skip empty lines
ID=$(journalctl --new-id128 | sed -n 2p)
: >/expected
printf $'\n\n\n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
: >/expected
printf $'<5>\n<6>\n<7>\n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# Remove trailing spaces
ID=$(journalctl --new-id128 | sed -n 2p)
printf "Trailing spaces\n">/expected
printf $'<5>Trailing spaces \t \n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
printf "Trailing spaces\n">/expected
printf $'Trailing spaces \t \n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# Don't remove leading spaces
ID=$(journalctl --new-id128 | sed -n 2p)
printf $' \t Leading spaces\n'>/expected
printf $'<5> \t Leading spaces\n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
printf $' \t Leading spaces\n'>/expected
printf $' \t Leading spaces\n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# --output-fields restricts output
ID=$(journalctl --new-id128 | sed -n 2p)
printf $'foo' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o export --output-fields=MESSAGE,FOO --output-fields=PRIORITY,MESSAGE -t "$ID" >/output
[[ $(grep -c . /output) -eq 8 ]]
grep -q '^__CURSOR=' /output
grep -q '^MESSAGE=foo$' /output
grep -q '^PRIORITY=6$' /output
grep '^FOO=' /output && { echo 'unexpected success'; exit 1; }
grep '^SYSLOG_FACILITY=' /output && { echo 'unexpected success'; exit 1; }

# `-b all` negates earlier use of -b (-b and -m are otherwise exclusive)
journalctl -b -1 -b all -m >/dev/null

# -b always behaves like -b0
journalctl -q -b-1 -b0 | head -1 >/expected
journalctl -q -b-1 -b  | head -1 >/output
cmp /expected /output
# ... even when another option follows (both of these should fail due to -m)
{ journalctl -ball -b0 -m 2>&1 || :; } | head -1 >/expected
{ journalctl -ball -b  -m 2>&1 || :; } | head -1 >/output
cmp /expected /output

# https://github.com/systemd/systemd/issues/13708
ID=$(systemd-id128 new)
systemd-cat -t "$ID" bash -c 'echo parent; (echo child) & wait' &
PID=$!
wait $PID
journalctl --sync
# We can drop this grep when https://github.com/systemd/systemd/issues/13937
# has a fix.
journalctl -b -o export -t "$ID" --output-fields=_PID | grep '^_PID=' >/output
[[ $(grep -c . /output) -eq 2 ]]
grep -q "^_PID=$PID" /output
grep -vq "^_PID=$PID" /output

# https://github.com/systemd/systemd/issues/15654
ID=$(journalctl --new-id128 | sed -n 2p)
printf "This will\nusually fail\nand be truncated\n">/expected
systemd-cat -t "$ID" /bin/sh -c 'env echo -n "This will";echo;env echo -n "usually fail";echo;env echo -n "and be truncated";echo;'
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output
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
[[ ! -f "/i-lose-my-logs" ]]

# https://github.com/systemd/systemd/issues/4408
rm -f /i-lose-my-logs
systemctl start forever-print-hola
sleep 3
systemctl kill --signal=SIGKILL systemd-journald
sleep 3
[[ ! -f "/i-lose-my-logs" ]]

# https://github.com/systemd/systemd/issues/15528
journalctl --follow --file=/var/log/journal/*/* | head -n1 || [[ $? -eq 1 ]]

function add_logs_filtering_override() {
    UNIT=${1:?}
    OVERRIDE_NAME=${2:?}
    LOG_FILTER=${3:-""}

    mkdir -p /etc/systemd/system/"$UNIT".d/
    echo "[Service]" >/etc/systemd/system/"$UNIT".d/"${OVERRIDE_NAME}".conf
    echo "LogFilterPatterns=$LOG_FILTER" >>/etc/systemd/system/"$UNIT".d/"${OVERRIDE_NAME}".conf
    systemctl daemon-reload
}

function run_service_and_fetch_logs() {
    UNIT=$1

    START=$(date '+%Y-%m-%d %T.%6N')
    systemctl restart "$UNIT"
    sleep .5
    journalctl --sync
    END=$(date '+%Y-%m-%d %T.%6N')

    journalctl -q -u "$UNIT" -S "$START" -U "$END" -p notice
    systemctl stop "$UNIT"
}

function is_xattr_supported() {
    START=$(date '+%Y-%m-%d %T.%6N')
    systemd-run --unit text_xattr --property LogFilterPatterns=log sh -c "sleep .5"
    sleep .5
    journalctl --sync
    END=$(date '+%Y-%m-%d %T.%6N')
    systemctl stop text_xattr

    ! journalctl -q -u "text_xattr" -S "$START" -U "$END" --grep "Failed to set 'user.journald_log_filter_patterns' xattr.*not supported$"
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
    add_logs_filtering_override "logs-filtering.service" "10-allow-with-escape-char" "\x7emore~"
    [[ -n $(run_service_and_fetch_logs "logs-filtering.service") ]]

    add_logs_filtering_override "delegated-cgroup-filtering.service" "00-allow-all" ".*"
    [[ -n $(run_service_and_fetch_logs "delegated-cgroup-filtering.service") ]]

    add_logs_filtering_override "delegated-cgroup-filtering.service" "01-discard-hello" "~hello"
    [[ -z $(run_service_and_fetch_logs "delegated-cgroup-filtering.service") ]]

    rm -rf /etc/systemd/system/logs-filtering.service.d
    rm -rf /etc/systemd/system/delegated-cgroup-filtering.service.d
fi

# Check that the seqnum field at least superficially works
systemd-cat echo "ya"
journalctl --sync
SEQNUM1=$(journalctl -o export -n 1 | grep -Ea "^__SEQNUM=" | cut -d= -f2)
systemd-cat echo "yo"
journalctl --sync
SEQNUM2=$(journalctl -o export -n 1 | grep -Ea "^__SEQNUM=" | cut -d= -f2)
test "$SEQNUM2" -gt "$SEQNUM1"

JTMP="/var/tmp/jtmp-$RANDOM"
mkdir "$JTMP"

( cd /test-journals/1 && for f in *.zst; do unzstd "$f" -o "$JTMP/${f%.zst}"; done )

journalctl --directory="$JTMP" --list-boots --output=json >/tmp/lb1

diff -u /tmp/lb1 - <<'EOF'
[{"index":-3,"boot_id":"5ea5fc4f82a14186b5332a788ef9435e","first_entry":1666569600994371,"last_entry":1666584266223608},{"index":-2,"boot_id":"bea6864f21ad4c9594c04a99d89948b0","first_entry":1666584266731785,"last_entry":1666584347230411},{"index":-1,"boot_id":"4c708e1fd0744336be16f3931aa861fb","first_entry":1666584348378271,"last_entry":1666584354649355},{"index":0,"boot_id":"35e8501129134edd9df5267c49f744a4","first_entry":1666584356661527,"last_entry":1666584438086856}]
EOF

rm -rf "$JTMP"

rm /tmp/lb1

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

touch /testok
