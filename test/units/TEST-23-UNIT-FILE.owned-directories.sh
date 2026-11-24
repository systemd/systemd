#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

unit=test-owned-directories.service
target=test-owned-directories.target
fragment=/run/systemd/system/$unit
state=/var/lib/test-owned-directories
cache=/var/cache/test-owned-directories
logs=/var/log/test-owned-directories

at_exit() {
    set +e
    systemctl stop "$target" "$unit"
    rm -f "$fragment" "/run/systemd/system/$target"
    rm -rf "$state" "$cache" "$logs"
    systemctl daemon-reload
}
trap at_exit EXIT

# Hold a reference independently of GC. Only the namespace sees the generated hidden/link.
printf '[Unit]\nWants=%s\n' "$unit" >"/run/systemd/system/$target"
mkdir -p "$state/hidden"
touch "$state/hidden/link"
cat >"$fragment" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
StateDirectory="test-owned-directories/old path:test-owned-directories/link"
StateDirectory="test-owned-directories/old path:test-owned-directories/hidden/link"
CacheDirectory=test-owned-directories/old-cache
TemporaryFileSystem=$state/hidden
ExecStart=test -L $state/hidden/link
EOF
systemctl daemon-reload
systemctl start "$target"
systemctl is-active "$unit"
test -L "$state/link"
test -f "$state/hidden/link"

# Loading a configuration, even when the named directory exists, is not evidence that it was set up.
mkdir "$state/never-ran" "$state/current"
printf '[Service]\nStateDirectory=test-owned-directories/never-ran\nExecStart=true\n' >"$fragment"
systemctl daemon-reload
printf '[Service]\nStateDirectory=test-owned-directories/current\nExecStart=true\n' >"$fragment"
systemctl daemon-reexec
systemctl stop "$unit"
systemctl clean --what=state "$unit"
test ! -e "$state/current"
test ! -e "$state/old path"
test ! -L "$state/link"
test -f "$state/hidden/link"
test -d "$state/never-ran"
test -d "$cache/old-cache"

rm "$fragment"
systemctl daemon-reload
test "$(systemctl show -P CanClean "$unit")" = cache
systemctl clean --what=cache "$unit"
test ! -e "$cache/old-cache"

# Directory setup can fail partway through. State was set up before cache failed; logs was never touched.
touch "$cache/blocker"
mkdir -p "$logs/unreached"
cat >"$fragment" <<EOF
[Service]
Type=oneshot
StateDirectory=test-owned-directories/partial
CacheDirectory=test-owned-directories/blocker/child
LogsDirectory=test-owned-directories/unreached
ExecStart=true
EOF
systemctl daemon-reload
(! systemctl start "$unit")
test -d "$state/partial"
rm "$fragment"
systemctl daemon-reload
systemctl reset-failed "$unit"
test "$(systemctl show -P CanClean "$unit")" = state
systemctl clean --what=all "$unit"
test ! -e "$state/partial"
test -d "$logs/unreached"
