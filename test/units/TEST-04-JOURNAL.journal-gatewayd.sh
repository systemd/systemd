#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [[ ! -x /usr/lib/systemd/systemd-journal-gatewayd ]]; then
    echo "Built without systemd-journal-gatewayd support, skipping the test"
    exit 0
fi

LOG_FILE="$(mktemp)"

at_exit() {
    if [[ $? -ne 0 ]]; then
        # The $LOG_FILE is potentially huge (as it might be a full copy of the current journal), so let's
        # dump it at debug level under a specific syslog tag, so it's clearly separated from the actual test
        # journal; things get very confusing otherwise.
        systemd-cat -t log-file-dump -p debug cat "$LOG_FILE"
    fi

    rm -f "$LOG_FILE"
}

trap at_exit EXIT

TEST_MESSAGE="-= This is a test message $RANDOM =-"
TEST_TAG="$(systemd-id128 new)"

BEFORE_TIMESTAMP="$(date +%s)"
echo "$TEST_MESSAGE" | systemd-cat -t "$TEST_TAG"
sleep 1
journalctl --sync
TEST_CURSOR="$(journalctl -q -t "$TEST_TAG" -n 0 --show-cursor | awk '{ print $3; }')"
BOOT_CURSOR="$(journalctl -q -b -n 0 --show-cursor | awk '{ print $3; }')"
AFTER_TIMESTAMP="$(date +%s)"

/usr/lib/systemd/systemd-journal-gatewayd --version
/usr/lib/systemd/systemd-journal-gatewayd --help

# Default configuration (HTTP, socket activated)
systemctl start systemd-journal-gatewayd.socket

# /browse
# We should get redirected to /browse by default
curl -LSfs http://localhost:19531 >"$LOG_FILE"
grep -qF "<title>Journal</title>" "$LOG_FILE"
curl -LSfs http://localhost:19531/browse >"$LOG_FILE"
grep -qF "<title>Journal</title>" "$LOG_FILE"
(! curl -LSfs http://localhost:19531/foo/bar/baz)
(! curl -LSfs http://localhost:19531/foo/../../../bar/../baz)

# /entries
# Accept: text/plain should be the default
curl -LSfs http://localhost:19531/entries >"$LOG_FILE"
grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE" "$LOG_FILE"
curl -LSfs --header "Accept: text/plain" http://localhost:19531/entries >"$LOG_FILE"
grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE" "$LOG_FILE"
curl -LSfs --header "Accept: application/json" http://localhost:19531/entries >"$LOG_FILE"
jq -se ".[] | select(.MESSAGE == \"$TEST_MESSAGE\")" "$LOG_FILE"
curl -LSfs --header "Accept: application/json" http://localhost:19531/entries?boot >"$LOG_FILE"
jq -se ".[] | select(.MESSAGE == \"$TEST_MESSAGE\")" "$LOG_FILE"
curl -LSfs --header "Accept: application/json" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
jq -se "length == 1 and select(.[].MESSAGE == \"$TEST_MESSAGE\")" "$LOG_FILE"
# Show 10 entries starting from $BOOT_CURSOR, skip the first 5
curl -LSfs \
     --header "Accept: application/json" \
     --header "Range: entries=$BOOT_CURSOR:5:10" \
     http://localhost:19531/entries >"$LOG_FILE"
jq -se "length == 10" "$LOG_FILE"
# Check if the specified cursor refers to an existing entry and return just that entry
curl -LSfs \
     --header "Accept: application/json" \
     --header "Range: entries=$TEST_CURSOR" \
     http://localhost:19531/entries?discrete >"$LOG_FILE"
jq -se "length == 1 and select(.[].MESSAGE == \"$TEST_MESSAGE\")" "$LOG_FILE"
# Check entry is present (resp. absent) when filtering by timestamp
curl -LSfs \
     --header "Range: realtime=$BEFORE_TIMESTAMP:" \
     http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE" "$LOG_FILE"
curl -LSfs \
     --header "Range: realtime=:$AFTER_TIMESTAMP" \
     http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE" "$LOG_FILE"
curl -LSfs \
     --header "Accept: application/json" \
     --header "Range: realtime=:$BEFORE_TIMESTAMP" \
     http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
jq -se "length == 0" "$LOG_FILE"
curl -LSfs \
     --header "Accept: application/json" \
     --header "Range: realtime=$AFTER_TIMESTAMP:" \
     http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
jq -se "length == 0" "$LOG_FILE"
# Check positive and negative skip when filtering by timestamp
echo "-= This is a second test message =-" | systemd-cat -t "$TEST_TAG"
journalctl --sync
TEST2_CURSOR="$(journalctl -q -t "$TEST_TAG" -n 0 --show-cursor | awk '{ print $3; }')"
echo "-= This is a third test message =-" | systemd-cat -t "$TEST_TAG"
journalctl --sync
sleep 1
END_TIMESTAMP="$(date +%s)"
curl -LSfs \
     --header "Accept: application/json" \
     --header "Range: realtime=$BEFORE_TIMESTAMP::1:1" \
     http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
jq -se "length == 1 and select(.[].__CURSOR == \"$TEST2_CURSOR\")" "$LOG_FILE"
curl -LSfs \
     --header "Accept: application/json" \
     --header "Range: realtime=$END_TIMESTAMP::-1:1" \
     http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" >"$LOG_FILE"
jq -se "length == 1 and select(.[].__CURSOR == \"$TEST2_CURSOR\")" "$LOG_FILE"

# No idea how to properly parse this (jq won't cut it), so let's at least do some sanity checks that every
# line is either empty or begins with data:
curl -LSfs --header "Accept: text/event-stream" http://localhost:19531/entries >"$LOG_FILE"
awk '!/^(data: \{.+\}|)$/ { exit 1; }' "$LOG_FILE"
# Same thing as journalctl --output=export
mkdir /tmp/remote-journal
curl -LSfs --header "Accept: application/vnd.fdo.journal" http://localhost:19531/entries >"$LOG_FILE"
/usr/lib/systemd/systemd-journal-remote --output=/tmp/remote-journal/system.journal --split-mode=none "$LOG_FILE"
journalctl --directory=/tmp/remote-journal -t "$TEST_TAG" --grep "$TEST_MESSAGE"
rm -rf /tmp/remote-journal/*
# Let's do the same thing again, but let systemd-journal-remote spawn curl itself
/usr/lib/systemd/systemd-journal-remote --url=http://localhost:19531/entries \
                                        --output=/tmp/remote-journal/system.journal \
                                        --split-mode=none
journalctl --directory=/tmp/remote-journal -t "$TEST_TAG" --grep "$TEST_MESSAGE"
rm -rf /tmp/remote-journal

# /machine
curl -LSfs http://localhost:19531/machine >"$LOG_FILE"
jq . "$LOG_FILE"

# /fields
curl -LSfs http://localhost:19531/fields/MESSAGE >"$LOG_FILE"
grep -qE -- "$TEST_MESSAGE" "$LOG_FILE"
curl -LSfs http://localhost:19531/fields/_TRANSPORT
(! curl -LSfs http://localhost:19531/fields)
(! curl -LSfs http://localhost:19531/fields/foo-bar-baz)

systemctl stop systemd-journal-gatewayd.{socket,service}

if ! command -v openssl >/dev/null; then
    echo "openssl command not available, skipping the HTTPS tests"
    exit 0
fi

# Generate a self-signed certificate for systemd-journal-gatewayd
#
# Note: older OpenSSL requires a config file with some extra options, unfortunately
cat >/tmp/openssl.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = CZ
L = Brno
O = Foo
OU = Bar
CN = localhost
EOF
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 7 \
            -config /tmp/openssl.conf \
            -keyout /tmp/key.pem -out /tmp/cert.pem
# Start HTTPS version of gatewayd via the systemd-socket-activate tool to give it some coverage as well
systemd-socket-activate --listen=19531 -- \
    /usr/lib/systemd/systemd-journal-gatewayd \
        --cert=/tmp/cert.pem \
        --key=/tmp/key.pem \
        --file="/var/log/journal/*/*.journal" &
GATEWAYD_PID=$!
sleep 1

# Do a limited set of tests, since the underlying code should be the same past the HTTPS transport
curl -LSfsk https://localhost:19531 >"$LOG_FILE"
grep -qF "<title>Journal</title>" "$LOG_FILE"
curl -LSfsk https://localhost:19531/entries >"$LOG_FILE"
grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE" "$LOG_FILE"
curl -LSfsk --header "Accept: application/json" https://localhost:19531/entries >"$LOG_FILE"
jq -se ".[] | select(.MESSAGE == \"$TEST_MESSAGE\")" "$LOG_FILE"
curl -LSfsk https://localhost:19531/machine >"$LOG_FILE"
jq . "$LOG_FILE"
curl -LSfsk https://localhost:19531/fields/_TRANSPORT

kill "$GATEWAYD_PID"

# Test a couple of error scenarios
GATEWAYD_FILE="$(mktemp /tmp/test-gatewayd-XXX.journal)"

/usr/lib/systemd/systemd-journal-remote --output="$GATEWAYD_FILE" --getter="journalctl -n5 -o export"
systemd-run --unit="test-gatewayd.service" --socket-property="ListenStream=19531" \
            /usr/lib/systemd/systemd-journal-gatewayd --file="$GATEWAYD_FILE"

# Call an unsupported endpoint together with some garbage data - gatewayd should not send garbage in return
# See: https://github.com/systemd/systemd/issues/9858
OUT="$(mktemp)"
for _ in {0..4}; do
    (! curl --fail-with-body -d "please process this🐱 $RANDOM" -L http://localhost:19531/upload | tee "$OUT")
    (! grep '[^[:print:]]' "$OUT")
done
(! curl --fail-with-body --upload-file "$GATEWAYD_FILE" -L http://localhost:19531/upload | tee "$OUT")
(! grep '[^[:print:]]' "$OUT")
rm -rf "$OUT"

curl -LSfs http://localhost:19531/browse >"$LOG_FILE"
grep -qF "<title>Journal</title>" "$LOG_FILE"
# Nuke the file behind the /browse endpoint
mv /usr/share/systemd/gatewayd/browse.html /usr/share/systemd/gatewayd/browse.html.bak
(! curl --fail-with-body -L http://localhost:19531/browse)
mv /usr/share/systemd/gatewayd/browse.html.bak /usr/share/systemd/gatewayd/browse.html
curl -LSfs http://localhost:19531/browse >"$LOG_FILE"
grep -qF "<title>Journal</title>" "$LOG_FILE"

# Nuke the journal file
mv "$GATEWAYD_FILE" "$GATEWAYD_FILE.bak"
(! curl --fail-with-body -L http://localhost:19531/fields/_PID)
mv "$GATEWAYD_FILE.bak" "$GATEWAYD_FILE"
curl -LSfs http://localhost:19531/fields/_PID

systemctl stop test-gatewayd.{socket,service}
rm -f "$GATEWAYD_FILE"
