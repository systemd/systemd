#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

rm -f /tmp/setcap
touch /tmp/setcap

systemd-tmpfiles --dry-run --create - <<EOF
k /tmp/setcap - - - - cap_setuid,cap_setgid=ep cap_setgid+i
EOF
cap="$(getcap /tmp/setcap)"
assert_not_in 'cap_setuid' "$cap"
assert_not_in 'cap_setgid' "$cap"

systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - cap_setuid,cap_setgid=ep cap_setgid+i
EOF
assert_in 'cap_setgid=eip cap_setuid[+]ep' "$(getcap /tmp/setcap)"

systemd-tmpfiles --create - <<EOF
k+ /tmp/setcap - - - - cap_setuid=
EOF
cap="$(getcap /tmp/setcap)"
assert_not_in 'cap_setuid' "$cap"
assert_in 'cap_setgid=eip' "$cap"

systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - cap_setuid=
EOF
cap="$(getcap /tmp/setcap)"
assert_not_in 'cap_setuid' "$cap"
assert_not_in 'cap_setgid' "$cap"

systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - cap_setuid=eip rootuid=1000
EOF

assert_in '[[]rootid=1000[]]' "$(getcap -n /tmp/setcap)"

rm -f /tmp/setcap

rm -rf /tmp/setcap-dir
mkdir /tmp/setcap-dir
touch /tmp/setcap-dir/file

systemd-tmpfiles --create - <<EOF
K /tmp/setcap-dir - - - - cap_setuid,cap_setgid=ep cap_setgid+i
EOF
assert_in 'cap_setgid=eip cap_setuid[+]ep' "$(getcap /tmp/setcap-dir/file)"

systemd-tmpfiles --create - <<EOF
K+ /tmp/setcap-dir - - - - cap_setuid=
EOF
cap="$(getcap /tmp/setcap-dir/file)"
assert_not_in 'cap_setuid' "$cap"
assert_in 'cap_setgid=eip' "$cap"

rm -rf /tmp/setcap-dir
