#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

restore_hostname() {
    if [[ -e /tmp/hostname.bak ]]; then
        mv /tmp/hostname.bak /etc/hostname
    else
        rm -f /etc/hostname
    fi
}

test_hostname() {
    local orig=

    if [[ -f /etc/hostname ]]; then
        cp /etc/hostname /tmp/hostname.bak
        orig=$(cat /etc/hostname)
    fi

    trap restore_hostname RETURN

    # should activate daemon and work
    if [[ -n "$orig" ]]; then
        assert_in "Static hostname: $orig" "$(hostnamectl)"
    fi
    assert_in "Kernel: $(uname -s) $(uname -r)" "$(hostnamectl)"

    # change hostname
    assert_rc 0 hostnamectl set-hostname testhost
    assert_eq "$(cat /etc/hostname)" "testhost"
    assert_in "Static hostname: testhost" "$(hostnamectl)"

    if [[ -n "$orig" ]]; then
        # reset to original
        assert_rc 0 hostnamectl set-hostname "$orig"
        assert_eq "$(cat /etc/hostname)" "$orig"
        assert_in "Static hostname: $orig" "$(hostnamectl)"
    fi
}

: >/failed

test_hostname

touch /testok
rm /failed
