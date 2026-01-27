#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

cleanup() {
    set +e
    userdel -r test-74-userdbctl
    groupdel test-74-userdbctl
}

trap cleanup EXIT

systemd-sysusers - <<EOF
u test-74-userdbctl - "Test user for TEST-74-AUX-UTILS.userdbctl.sh" / /bin/bash
EOF

# Root
userdbctl user root
userdbctl user 0

# Nobody
userdbctl user 65534

# The 16bit and 32bit -1 user cannot exist
(! userdbctl user 65535)
(! userdbctl user 4294967295)

userdbctl user foreign-0
userdbctl user 2147352576
userdbctl user foreign-1
userdbctl user 2147352577
userdbctl user foreign-65534
userdbctl user 2147418110
(! userdbctl user foreign-65535)
(! userdbctl user 2147418111)
(! userdbctl user foreign-65536)
(! userdbctl user 2147418112)

assert_eq "$(userdbctl user root -j | jq .uid)" 0
assert_eq "$(userdbctl user foreign-0 -j | jq .uid)" 2147352576
assert_eq "$(userdbctl user foreign-1 -j | jq .uid)" 2147352577
assert_eq "$(userdbctl user foreign-65534 -j | jq .uid)" 2147418110

assert_eq "$(userdbctl user 0 -j | jq -r .userName)" root
assert_eq "$(userdbctl user 2147352576 -j | jq -r .userName)" foreign-0
assert_eq "$(userdbctl user 2147352577 -j | jq -r .userName)" foreign-1
assert_eq "$(userdbctl user 2147418110 -j | jq -r .userName)" foreign-65534

# Make sure that -F shows same data as if we'd ask directly
userdbctl user root -j | userdbctl -F- user  | cmp - <(userdbctl user root)
userdbctl user test-74-userdbctl -j | userdbctl -F- user  | cmp - <(userdbctl user test-74-userdbctl)
userdbctl user 65534 -j | userdbctl -F- user  | cmp - <(userdbctl user 65534)

userdbctl group root -j | userdbctl -F- group  | cmp - <(userdbctl group root)
userdbctl group test-74-userdbctl -j | userdbctl -F- group  | cmp - <(userdbctl group test-74-userdbctl)
userdbctl group 65534 -j | userdbctl -F- group  | cmp - <(userdbctl group 65534)

# Ensure NSS doesn't try to automount via open_tree
if [[ ! -v ASAN_OPTIONS ]]; then
    systemctl stop systemd-userdbd.socket systemd-userdbd.service
    set +o pipefail
    systemd-run -q -t --property SystemCallFilter=~open_tree id definitelynotarealuser | grep -q "no such user"
    systemd-run -q -t --property SystemCallFilter=~open_tree id --groups definitelynotarealuser | grep -q "no such user"
    systemd-run -q -t --property SystemCallFilter=~open_tree groups definitelynotarealuser | grep -q "no such user"
    set -o pipefail
    # getent shows no output when the entry is not found, but exists with 2, while sd-run crashing will exit
    # with 1
    assert_rc 2 systemd-run -q -t --property SystemCallFilter=~open_tree getent passwd definitelynotarealuser
    assert_rc 2 systemd-run -q -t --property SystemCallFilter=~open_tree getent group definitelynotarealgroup
    systemctl start systemd-userdbd.socket systemd-userdbd.service
fi

# For issue 40228
UNIT="sleep$RANDOM"
DISK_GID=$(userdbctl -j group disk | jq .gid)
systemd-run -p DynamicUser=yes -p Group=disk -u "$UNIT" sleep infinity
userdbctl group disk | grep -F 'io.systemd.NameServiceSwitch' >/dev/null
userdbctl group "$DISK_GID" | grep -F 'io.systemd.NameServiceSwitch' >/dev/null
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LookupDynamicUserByName "s" disk)
(! busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LookupDynamicUserByUID "u" "$DISK_GID")
systemctl stop "$UNIT"
