#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-tmpfiles --create - <<EOF
f /tmp/xxx1 0644 - - - foo
f /tmp/xxx2 0644 - - - foo bar
f /tmp/xxx3 0644 - - - foo\x20bar
f /tmp/xxx4 0644 - - - \x20foobar
f /tmp/xxx5 0644 - - - foobar\x20
f /tmp/xxx6 0644 - - -  foo bar
f /tmp/xxx7 0644 - - -  foo bar \n
f /tmp/xxx8 0644 - - - " foo bar "
f /tmp/xxx9 0644 - - - ' foo bar '
EOF

echo -n "foo" | cmp /tmp/xxx1 -
echo -n "foo bar" | cmp /tmp/xxx2 -
echo -n "foo bar" | cmp /tmp/xxx3 -
echo -n " foobar" | cmp /tmp/xxx4 -
echo -n "foobar " | cmp /tmp/xxx5 -
echo -n "foo bar" | cmp /tmp/xxx6 -
echo "foo bar " | cmp /tmp/xxx7 -
echo -n "\" foo bar \"" | cmp /tmp/xxx8 -
echo -n "' foo bar '" | cmp /tmp/xxx9 -

rm /tmp/xxx{1,2,3,4,5,6,7,8,9}
