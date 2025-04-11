#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test for queued events serialization on stop and deserialization on start

rules="/run/udev/rules.d/99-test-17.serialization.rules"

mkdir -p "${rules%/*}"
cat > "$rules" <<'EOF'
SUBSYSTEM!="mem", GOTO="end"
KERNEL!="null", GOTO="end"
ACTION=="remove", GOTO="end"

IMPORT{db}="INVOCATIONS"
IMPORT{program}="/bin/bash -c 'systemctl show --property=InvocationID systemd-udevd.service'"
ENV{INVOCATIONS}+="%E{ACTION}_%E{SEQNUM}_%E{InvocationID}"
ACTION=="add", RUN+="/bin/bash -c ':> /tmp/marker'", RUN+="/usr/bin/sleep 10"

LABEL="end"
EOF

udevadm control --reload --log-level=debug

udevadm settle --timeout 30
rm -f /tmp/marker

INVOCATION_BEFORE="$(systemctl show --property=InvocationID --value systemd-udevd.service)"

for action in remove add change change change change; do
    udevadm trigger --action="$action" /dev/null
done

timeout 10 bash -c 'until test -e /tmp/marker; do sleep .1; done'
systemctl restart systemd-udevd.service
udevadm settle --timeout 30

INVOCATION_AFTER="$(systemctl show --property=InvocationID --value systemd-udevd.service)"

udevadm info --no-pager /dev/null

previous_seqnum=0
expected_action=add
expected_invocation="$INVOCATION_BEFORE"
count=0
while read -r action seqnum invocation; do
    test "$seqnum" -gt "$previous_seqnum"
    assert_eq "$action" "$expected_action"
    assert_eq "$invocation" "$expected_invocation"

    previous_seqnum="$seqnum"
    expected_action=change
    expected_invocation="$INVOCATION_AFTER"
    : $((++count))
done < <(udevadm info -q property --property=INVOCATIONS --value /dev/null | sed -e 's/ /\n/g; s/_/ /g')

assert_eq "$count" "5"

rm -f "$rules" /tmp/marker
udevadm control --reload

exit 0
