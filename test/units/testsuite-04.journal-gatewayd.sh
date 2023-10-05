#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
# pipefail is disabled intentionally, as `curl | grep -q` is very SIGPIPE happy

if [[ ! -x /usr/lib/systemd/systemd-journal-gatewayd ]]; then
    echo "Built without systemd-journal-gatewayd support, skipping the test"
    exit 0
fi

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
curl -Lfs http://localhost:19531 | grep -qF "<title>Journal</title>"
curl -Lfs http://localhost:19531/browse | grep -qF "<title>Journal</title>"
(! curl -Lfs http://localhost:19531/foo/bar/baz)
(! curl -Lfs http://localhost:19531/foo/../../../bar/../baz)

# /entries
# Accept: text/plain should be the default
curl -Lfs http://localhost:19531/entries | \
    grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE"
curl -Lfs --header "Accept: text/plain" http://localhost:19531/entries | \
    grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE"
curl -Lfs --header "Accept: application/json" http://localhost:19531/entries | \
    jq -se ".[] | select(.MESSAGE == \"$TEST_MESSAGE\")"
curl -Lfs --header "Accept: application/json" http://localhost:19531/entries?boot | \
    jq -se ".[] | select(.MESSAGE == \"$TEST_MESSAGE\")"
curl -Lfs --header "Accept: application/json" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    jq -se "length == 1 and select(.[].MESSAGE == \"$TEST_MESSAGE\")"
# Show 10 entries starting from $BOOT_CURSOR, skip the first 5
curl -Lfs --header "Accept: application/json" --header "Range: entries=$BOOT_CURSOR:5:10" http://localhost:19531/entries | \
    jq -se "length == 10"
# Check if the specified cursor refers to an existing entry and return just that entry
curl -Lfs --header "Accept: application/json" --header "Range: entries=$TEST_CURSOR" http://localhost:19531/entries?discrete | \
    jq -se "length == 1 and select(.[].MESSAGE == \"$TEST_MESSAGE\")"
# Check entry is present (resp. absent) when filtering by timestamp
curl -Lfs --header "Range: realtime=$BEFORE_TIMESTAMP:" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE"
curl -Lfs --header "Range: realtime=:$AFTER_TIMESTAMP" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE"
curl -Lfs --header "Accept: application/json" --header "Range: realtime=:$BEFORE_TIMESTAMP" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    jq -se "length == 0"
curl -Lfs --header "Accept: application/json" --header "Range: realtime=$AFTER_TIMESTAMP:" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    jq -se "length == 0"
# Check positive and negative skip when filtering by timestamp
echo "-= This is a second test message =-" | systemd-cat -t "$TEST_TAG"
journalctl --sync
TEST2_CURSOR="$(journalctl -q -t "$TEST_TAG" -n 0 --show-cursor | awk '{ print $3; }')"
echo "-= This is a third test message =-" | systemd-cat -t "$TEST_TAG"
journalctl --sync
sleep 1
END_TIMESTAMP="$(date +%s)"
curl -Lfs --header "Accept: application/json" --header "Range: realtime=$BEFORE_TIMESTAMP::1:1" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    jq -se "length == 1 and select(.[].__CURSOR == \"$TEST2_CURSOR\")"
curl -Lfs --header "Accept: application/json" --header "Range: realtime=$END_TIMESTAMP::-1:1" http://localhost:19531/entries?SYSLOG_IDENTIFIER="$TEST_TAG" | \
    jq -se "length == 1 and select(.[].__CURSOR == \"$TEST2_CURSOR\")"

# No idea how to properly parse this (jq won't cut it), so let's at least do some sanity checks that every
# line is either empty or begins with data:
curl -Lfs --header "Accept: text/event-stream" http://localhost:19531/entries | \
    awk '!/^(data: \{.+\}|)$/ { exit 1; }'
# Same thing as journalctl --output=export
mkdir /tmp/remote-journal
curl -Lfs --header "Accept: application/vnd.fdo.journal" http://localhost:19531/entries | \
    /usr/lib/systemd/systemd-journal-remote --output=/tmp/remote-journal/system.journal --split-mode=none -
journalctl --directory=/tmp/remote-journal -t "$TEST_TAG" --grep "$TEST_MESSAGE"
rm -rf /tmp/remote-journal/*
# Let's do the same thing again, but let systemd-journal-remote spawn curl itself
/usr/lib/systemd/systemd-journal-remote --url=http://localhost:19531/entries \
                                        --output=/tmp/remote-journal/system.journal \
                                        --split-mode=none
journalctl --directory=/tmp/remote-journal -t "$TEST_TAG" --grep "$TEST_MESSAGE"
rm -rf /tmp/remote-journal

# /machine
curl -Lfs http://localhost:19531/machine | jq

# /fields
curl -Lfs http://localhost:19531/fields/MESSAGE | grep -qE -- "$TEST_MESSAGE"
curl -Lfs http://localhost:19531/fields/_TRANSPORT
(! curl -Lfs http://localhost:19531/fields)
(! curl -Lfs http://localhost:19531/fields/foo-bar-baz)

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
curl -Lfsk https://localhost:19531 | grep -qF "<title>Journal</title>"
curl -Lfsk https://localhost:19531/entries | \
    grep -qE " $TEST_TAG\[[0-9]+\]: $TEST_MESSAGE"
curl -Lfsk --header "Accept: application/json" https://localhost:19531/entries | \
    jq -se ".[] | select(.MESSAGE == \"$TEST_MESSAGE\")"
curl -Lfsk https://localhost:19531/machine | jq
curl -Lfsk https://localhost:19531/fields/_TRANSPORT

kill "$GATEWAYD_PID"
