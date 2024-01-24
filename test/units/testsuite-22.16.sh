#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test for conditionalized execute bit ('X' bit)
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

rm -f /tmp/acl_exec
touch /tmp/acl_exec

# No ACL set yet
systemd-tmpfiles --dry-run --create - <<EOF
a /tmp/acl_exec - - - - u:root:rwX
EOF
assert_not_in 'user:root:rw-' "$(getfacl -Ec /tmp/acl_exec)"

systemd-tmpfiles --create - <<EOF
a /tmp/acl_exec - - - - u:root:rwX
EOF
assert_in 'user:root:rw-' "$(getfacl -Ec /tmp/acl_exec)"

# Set another ACL and append
setfacl -m g:root:x /tmp/acl_exec

systemd-tmpfiles --create - <<EOF
a+ /tmp/acl_exec - - - - u:root:rwX
EOF
acl="$(getfacl -Ec /tmp/acl_exec)"
assert_in 'user:root:rwx' "$acl"
assert_in 'group:root:--x' "$acl"

# Reset ACL (no append)
systemd-tmpfiles --create - <<EOF
a /tmp/acl_exec - - - - u:root:rwX
EOF
assert_in 'user:root:rw-' "$(getfacl -Ec /tmp/acl_exec)"

rm -f /tmp/acl_exec
