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

# '=' resets the listed capabilities, so a later clause overrides an earlier one
systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - cap_setuid,cap_setgid=ep cap_setuid=
EOF
cap="$(getcap /tmp/setcap)"
assert_not_in 'cap_setuid' "$cap"
assert_in 'cap_setgid=ep$' "$cap"

systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - cap_setuid=ep cap_setuid=p
EOF
assert_in 'cap_setuid=p$' "$(getcap /tmp/setcap)"

# A clause may contain several actions. Use a capability that is not set yet, so that an ignored line
# would be noticed.
systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - cap_setgid+ep-e
EOF
cap="$(getcap /tmp/setcap)"
assert_not_in 'cap_setuid' "$cap"
assert_in 'cap_setgid=p$' "$cap"

# '+' and '-' without flags, unknown flags and '=' after the first action are invalid, so the line is
# ignored and the file is left alone
for arg in 'cap_setuid+' 'cap_setuid=ep-' 'cap_setuid+x' 'cap_setuid=ep+q' 'cap_setuid=p=e' 'cap_setuid=ep='; do
    systemd-tmpfiles --create - <<EOF
k /tmp/setcap - - - - $arg
EOF
    assert_in 'cap_setgid=p$' "$(getcap /tmp/setcap)"
done

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
