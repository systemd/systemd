#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test for queued events serialization on stop and deserialization on start.

rules="/run/udev/rules.d/99-test-17.serialization.rules"

mkdir -p "${rules%/*}"
cat > "$rules" <<'EOF'
SUBSYSTEM!="mem", GOTO="end"
KERNEL!="null", GOTO="end"
ACTION=="remove", GOTO="end"

IMPORT{db}="INVOCATIONS"
IMPORT{program}="/usr/bin/bash -c 'systemctl show --property=InvocationID systemd-udevd.service'"
ENV{INVOCATIONS}+="%E{ACTION}_%E{SEQNUM}_%E{InvocationID}"
ACTION=="add", RUN+="/usr/bin/bash -c ':> /tmp/marker'", RUN+="/usr/bin/sleep 10"

LABEL="end"
EOF

udevadm control --reload

udevadm settle --timeout 30
rm -f /tmp/marker

# Save the current invocation ID of udevd.
INVOCATION_BEFORE="$(systemctl show --property=InvocationID --value systemd-udevd.service)"

# Trigger several actions.
# The first 'add' event should be processed by the current invocation.
for action in remove add change change change change; do
    udevadm trigger --action="$action" /dev/null
done

# While processing the first 'add' event, request restarting udevd.
# Hence, the queued subsequent 'change' events should be serialized,
# then deserialized, requeued, and processed in the next invocation.
timeout 10 bash -c 'until test -e /tmp/marker; do sleep .1; done'
systemctl restart systemd-udevd.service
udevadm settle --timeout 30

# Get the invocation ID of the restarted udevd.
INVOCATION_AFTER="$(systemctl show --property=InvocationID --value systemd-udevd.service)"

udevadm info --no-pager /dev/null

# Check the properties that records action, seqnum, and invocation ID.
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

# Check the total number of events processed by the udevd.
assert_eq "$count" "5"

rm -f "$rules" /tmp/marker
udevadm control --reload

exit 0
