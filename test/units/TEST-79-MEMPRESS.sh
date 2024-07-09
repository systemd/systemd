#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# We not just test if the file exists, but try to read from it, since if
# CONFIG_PSI_DEFAULT_DISABLED is set in the kernel the file will exist and can
# be opened, but any read()s will fail with EOPNOTSUPP, which we want to
# detect.
if ! cat /proc/pressure/memory >/dev/null ; then
    echo "kernel too old, has no PSI." >&2
    echo OK >/testok
    exit 0
fi

systemd-analyze log-level debug

CGROUP=/sys/fs/cgroup/"$(systemctl show TEST-79-MEMPRESS.service -P ControlGroup)"
test -d "$CGROUP"

if ! test -f "$CGROUP"/memory.pressure ; then
    echo "No memory accounting/PSI delegated via cgroup, can't test." >&2
    echo OK >/testok
    exit 0
fi

UNIT="test-mempress-$RANDOM.service"
SCRIPT="/tmp/mempress-$RANDOM.sh"

cat >"$SCRIPT" <<'EOF'
#!/bin/bash

set -ex

export
id

test -n "$MEMORY_PRESSURE_WATCH"
test "$MEMORY_PRESSURE_WATCH" != /dev/null
test -w "$MEMORY_PRESSURE_WATCH"

ls -al "$MEMORY_PRESSURE_WATCH"

EXPECTED="$(echo -n -e "some 123000 2000000\x00" | base64)"

test "$EXPECTED" = "$MEMORY_PRESSURE_WRITE"

EOF

chmod +x "$SCRIPT"

systemd-run \
    -u "$UNIT" \
    -p Type=exec \
    -p ProtectControlGroups=1 \
    -p DynamicUser=1 \
    -p MemoryPressureWatch=on \
    -p MemoryPressureThresholdSec=123ms \
    -p BindPaths=$SCRIPT \
    `# Make sanitizers happy when DynamicUser=1 pulls in instrumented systemd NSS modules` \
    -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
    --wait "$SCRIPT"

rm "$SCRIPT"

systemd-analyze log-level info

touch /testok
