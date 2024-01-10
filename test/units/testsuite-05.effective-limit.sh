#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

pre=test05
cat >/run/systemd/system/"$pre"alpha.slice <<EOF
[Slice]
MemoryMax=40M
MemoryHigh=40M
TasksMax=400
EOF

cat >/run/systemd/system/"$pre"alpha-beta.slice <<EOF
[Slice]
MemoryMax=10M
MemoryHigh=10M
TasksMax=100
EOF

cat >/run/systemd/system/"$pre"alpha-beta-gamma.slice <<EOF
[Slice]
MemoryMax=20M
MemoryHigh=20M
TasksMax=200
EOF

systemctl daemon-reload

srv=probe.service
slc0="$pre"alpha.slice
slc="$pre"alpha-beta-gamma.slice

systemd-run --unit "$srv" --slice "$slc"  \
    -p MemoryMax=5M \
    -p MemoryHigh=5M \
    -p TasksMax=50 \
    sleep inf

# Compare with inequality because test can run in a constrained container
assert_le "$(systemctl show -P EffectiveMemoryMax "$srv")" "5242880"
assert_le "$(systemctl show -P EffectiveMemoryHigh "$srv")" "5242880"
assert_le "$(systemctl show -P EffectiveTasksMax "$srv")" "50"

systemctl stop "$srv"

systemd-run --unit "$srv" --slice "$slc"  \
    sleep inf

assert_le "$(systemctl show -P EffectiveMemoryMax "$srv")" "10485760"
assert_le "$(systemctl show -P EffectiveMemoryHigh "$srv")" "10485760"
assert_le "$(systemctl show -P EffectiveTasksMax "$srv")" "100"

systemctl set-property "$slc0" \
    MemoryMax=5M \
    MemoryHigh=5M \
    TasksMax=50

assert_le "$(systemctl show -P EffectiveMemoryMax "$srv")" "5242880"
assert_le "$(systemctl show -P EffectiveMemoryHigh "$srv")" "5242880"
assert_le "$(systemctl show -P EffectiveTasksMax "$srv")" "50"

systemctl stop "$srv"

rm -f /run/systemd/system/"$pre"* || :
