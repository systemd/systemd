#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

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
userdbctl user systemd-network -j | userdbctl -F- user  | cmp - <(userdbctl user systemd-network)
userdbctl user 65534 -j | userdbctl -F- user  | cmp - <(userdbctl user 65534)

userdbctl group root -j | userdbctl -F- group  | cmp - <(userdbctl group root)
userdbctl group systemd-network -j | userdbctl -F- group  | cmp - <(userdbctl group systemd-network)
userdbctl group 65534 -j | userdbctl -F- group  | cmp - <(userdbctl group 65534)
