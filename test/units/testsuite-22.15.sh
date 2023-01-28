#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Check specifier expansion in L lines.
#
set -eux

rm -fr /tmp/L
mkdir  /tmp/L

# Check that %h expands to $home.
home='/somewhere'
dst='/tmp/L/1'
src="$home"
HOME="$home" \
systemd-tmpfiles --create - <<EOF
L     $dst    - - - - %h
EOF
test "$(readlink "$dst")" = "$src"

# Check that %h in the path is expanded, but
# the result of this expansion is not expanded once again.
root='/tmp/L/2'
home='/%U'
src="/usr/share/factory$home"
mkdir -p "$root$src"
dst="$root$home"
HOME="$home" \
systemd-tmpfiles --create --root="$root" - <<EOF
L     %h    - - - -
EOF
test "$(readlink "$dst")" = "$src"
