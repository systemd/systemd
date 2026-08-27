#!/usr/bin/env bash
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

# An ACL mask without execute suppresses execute from masked ACL entries
setfacl -b -m g:root:x,m::rw- /tmp/acl_exec

systemd-tmpfiles --create - <<EOF
a+ /tmp/acl_exec - - - - u:root:rwX
EOF
acl="$(getfacl -Ec /tmp/acl_exec)"
assert_in 'user:root:rw-' "$acl"
assert_in 'group:root:--x' "$acl"
assert_in 'mask::rw-' "$acl"

# The mask also suppresses execute from the owning group when replacing ACLs
setfacl -b -m g::x,m::rw- /tmp/acl_exec

systemd-tmpfiles --create - <<EOF
a /tmp/acl_exec - - - - u:root:rwX
EOF
acl="$(getfacl -Ec /tmp/acl_exec)"
assert_in 'user:root:rw-' "$acl"
assert_in 'mask::rw-' "$acl"

# Reset ACL (no append)
systemd-tmpfiles --create - <<EOF
a /tmp/acl_exec - - - - u:root:rwX
EOF
assert_in 'user:root:rw-' "$(getfacl -Ec /tmp/acl_exec)"

# ACL_USER_OBJ carries execute; mask does not
chmod 744 /tmp/acl_exec
setfacl -b -m u:root:rw,m::rw /tmp/acl_exec
systemd-tmpfiles --create - <<EOF
a+ /tmp/acl_exec - - - - u:root:rwX
EOF
assert_in 'user:root:rwx' "$(getfacl -Ec /tmp/acl_exec)"

# ACL_OTHER carries execute; mask does not
chmod 645 /tmp/acl_exec
setfacl -b -m u:root:rw,m::rw /tmp/acl_exec
systemd-tmpfiles --create - <<EOF
a+ /tmp/acl_exec - - - - u:root:rwX
EOF
assert_in 'user:root:rwx' "$(getfacl -Ec /tmp/acl_exec)"

rm -f /tmp/acl_exec

# Recursive ACL rules should not flip the execute bit on newly created files
rm -rf /tmp/acl_dir
mkdir -p /tmp/acl_dir
systemd-tmpfiles --create - <<EOF
A /tmp/acl_dir - - - - u::rwX,g::rwX,m::rwX,d:m::rwX
EOF
acl="$(getfacl -Ec /tmp/acl_dir)"
assert_in 'user::rwx' "$acl"
assert_in 'group::rwx' "$acl"
assert_in 'mask::rwx' "$acl"
assert_in 'default:user::rwx' "$acl"
assert_in 'default:group::rwx' "$acl"
assert_in 'default:mask::rwx' "$acl"

touch /tmp/acl_dir/test_default_acl_file
acl="$(getfacl -Ec /tmp/acl_dir/test_default_acl_file)"
assert_in 'user::rw-' "$acl"
assert_in 'group::rwx' "$acl"
assert_in 'mask::rw-' "$acl"

systemd-tmpfiles --create - <<EOF
A /tmp/acl_dir - - - - u::rwX,g::rwX,m::rwX,d:m::rwX
EOF
acl="$(getfacl -Ec /tmp/acl_dir/test_default_acl_file)"
assert_in 'user::rw-' "$acl"
assert_in 'group::rw-' "$acl"
assert_in 'mask::rw-' "$acl"

rm -rf /tmp/acl_dir
