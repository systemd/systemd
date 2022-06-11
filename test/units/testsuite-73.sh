#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

restore_locale() {
    rmdir /usr/lib/locale/xx_XX.UTF-8

    if [[ -f /tmp/locale.conf.bak ]]; then
        mv /tmp/locale.conf.bak /etc/locale.conf
    else
        rm -f /etc/locale.conf
    fi

    if [[ -f /tmp/locale.gen.bak ]]; then
        mv /tmp/locale.gen.bak /etc/locale.gen
    else
        rm -f /etc/locale.gen
    fi

    if command -v locale-gen >/dev/null 2>&1; then
        locale-gen
    fi
}

test_locale() {
    local i

    if [[ -f /etc/locale.conf ]]; then
        cp /etc/locale.conf /tmp/locale.conf.bak
    fi

    if [[ -f /etc/locale.gen ]]; then
        cp /etc/locale.gen /tmp/locale.gen.bak
    fi

    trap restore_locale EXIT

    if command -v locale-gen >/dev/null 2>&1 &&
           ! localectl list-locales | grep -F "en_US.UTF-8"; then
        # ensure at least one utf8 locale exist
        echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
        locale-gen en_US.UTF-8
    fi

    # create invalid locale
    mkdir /usr/lib/locale/xx_XX.UTF-8
    assert_not_in "xx_XX.UTF-8" "$(localectl list-locales)"

    if [[ -z "$(localectl list-locales)" ]]; then
        echo "No locale installed, skipping test."
        restore_locale
        trap - EXIT
        return
    fi

    # should activate daemon and work
    assert_in "System Locale:" "$(localectl)"

    # change locale
    for i in $(localectl list-locales); do
        assert_rc 0 localectl set-locale "$i"
        assert_in "LANG=$i" "$(cat /etc/locale.conf)"
        assert_in "System Locale: LANG=$i" "$(localectl)"

        assert_rc 0 localectl set-locale "LANG=C" "LC_CTYPE=$i"
        assert_eq "$(cat /etc/locale.conf)" "LANG=C
LC_CTYPE=$i"
        assert_in "System Locale: LANG=C" "$(localectl)"
        assert_in "LC_CTYPE=$i" "$(localectl)"
    done

    # test if localed auto-runs locale-gen
    if command -v locale-gen >/dev/null 2>&1 &&
           ! localectl list-locales | grep -F "de_DE.UTF-8"; then

        # clear previous locale
        systemctl stop systemd-localed.service
        rm -f /etc/locale.conf
        sync

        # change locale
        assert_rc 0 localectl set-locale de_DE.UTF-8
        assert_in "LANG=de_DE.UTF-8" "$(cat $LOCALE_CONF)"
        assert_in "System Locale: LANG=de_DE.UTF-8" "$(localectl)"

        # ensure tested locale exists and works now
        assert_in "de_DE.UTF-8" "$(localectl list-locales)"
    fi

    # reset locale to original
    restore_locale
    trap - EXIT
}

backup_keymap() {
    if [[ -f /etc/vconsole.conf ]]; then
        cp /etc/vconsole.conf /tmp/vconsole.conf.bak
    fi

    if [[ -f /etc/X11/xorg.conf.d/00-keyboard.conf ]]; then
        cp /etc/X11/xorg.conf.d/00-keyboard.conf /tmp/00-keyboard.conf.bak
    fi
}

restore_keymap() {
    if [[ -f /tmp/vconsole.conf.bak ]]; then
        mv /tmp/vconsole.conf.bak /etc/vconsole.conf
    else
        rm -f /etc/vconsole.conf
    fi

    if [[ -f /tmp/00-keyboard.conf.bak ]]; then
        mv /tmp/00-keyboard.conf.bak /etc/X11/xorg.conf.d/00-keyboard.conf
    else
        rm -f /etc/X11/xorg.conf.d/00-keyboard.conf
    fi
}

test_vc_keymap() {
    local i

    if [[ -z "$(localectl list-keymaps)" ]]; then
        echo "No vconsole keymap installed, skipping test."
        return
    fi

    backup_keymap
    trap restore_keymap EXIT

    # should activate daemon and work
    assert_in "VC Keymap:" "$(localectl)"

    # change vc layout
    for i in $(localectl list-keymaps); do
        # clear previous conversion from VC -> X11 keymap
        systemctl stop systemd-localed.service
        rm -f /etc/X11/xorg.conf.d/00-keyboard.conf

        assert_rc 0 localectl set-keymap "$i"
        assert_in "KEYMAP=$i" "$(cat /etc/vconsole.conf)"
        assert_in "VC Keymap: $i" "$(localectl)"
        if [[ "$i" == "us" ]]; then
            assert_in "X11 Layout: us" "$(localectl)"
            assert_in "X11 Model: pc105+inet" "$(localectl)"
        elif [[ "$i" == "us-acentos" ]]; then
            assert_in "X11 Layout: us" "$(localectl)"
            assert_in 'X11 Model: pc105$' "$(localectl)"
        elif [[ "$i" =~ ^us-.* ]]; then
            assert_in "X11 Layout: n/a" "$(localectl)"
            assert_not_in "X11 Model:" "$(localectl)"
        fi
    done

    # gets along without config file
    systemctl stop systemd-localed.service
    rm -f /etc/vconsole.conf
    assert_in "VC Keymap: n/a" "$(localectl)"

    restore_keymap
    trap - EXIT
}

test_x11_keymap() {
    if [[ -z "$(localectl list-x11-keymap-layouts)" ]]; then
        echo "No x11 keymap installed, skipping test."
        return
    fi

    backup_keymap
    trap restore_keymap EXIT

    # should activate daemon and work
    assert_in "X11 Layout:" "$(localectl)"

    # change x11 layout
    assert_rc 0 localectl set-x11-keymap us pc105+inet
    assert_in 'Option "XkbLayout" "us' "$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)"
    assert_in 'Option "XkbModel" "pc105+inet"' "$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)"
    assert_in "X11 Layout: us" "$(localectl)"
    assert_in "X11 Model: pc105+inet" "$(localectl)"

    # gets along without config file
    systemctl stop systemd-localed.service
    rm -f /etc/X11/xorg.conf.d/00-keyboard.conf
    assert_in "X11 Layout: n/a" "$(localectl)"

    # reset keymap to original
    restore_keymap
    trap - EXIT
}

: >/failed

test_locale
test_vc_keymap
test_x11_keymap

touch /testok
rm /failed
