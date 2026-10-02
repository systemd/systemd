#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Tests for systemctl --completion-names
set -ex

# Silence warning from running_in_chroot_or_offline()
export SYSTEMD_IN_CHROOT=0

systemctl=${1:-systemctl}

unset root
cleanup() {
    [ -n "$root" ] && rm -rf "$root"
}
trap cleanup exit
root=$(mktemp -d --tmpdir completion-test.XXXXXX)

: '-------list-unit-files: names and .service base names, templates included---'
mkdir -p "$root/etc/systemd/system"
# Empty unit files count as masked, hence give them some content
for unit in foo.service bar.socket templ@.service; do
    echo '[Unit]' >"$root/etc/systemd/system/$unit"
done
ln -s /dev/null "$root/etc/systemd/system/masked.service"

"$systemctl" --root="$root" list-unit-files --completion-names >"$root/out"
diff -u - "$root/out" <<EOF
foo.service
foo
masked.service
masked
templ@.service
templ@
bar.socket
EOF

: '-------list-unit-files: state and pattern filters still apply------------'
"$systemctl" --root="$root" list-unit-files --completion-names --state=masked >"$root/out"
diff -u - "$root/out" <<EOF
masked.service
masked
EOF

"$systemctl" --root="$root" list-unit-files --completion-names 'f*' >"$root/out"
diff -u - "$root/out" <<EOF
foo.service
foo
EOF

: '-------list-unit-files: no match fails like without --completion-names---'
( ! "$systemctl" --root="$root" list-unit-files --completion-names 'nonexistent*' >"$root/out" )
test ! -s "$root/out"

: '-------list-unit-files: output does not depend on option order-----------'
"$systemctl" --root="$root" list-unit-files --completion-names >"$root/expected"
"$systemctl" --root="$root" list-unit-files --legend=yes --completion-names >"$root/out"
diff -u "$root/expected" "$root/out"
"$systemctl" --root="$root" list-unit-files --completion-names --legend=yes >"$root/out"
diff -u "$root/expected" "$root/out"

: '-------other verbs reject --completion-names-----------------------------'
( ! "$systemctl" --root="$root" is-enabled --completion-names foo.service )
