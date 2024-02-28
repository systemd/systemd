#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

maybe_mount_usr_overlay
trap 'maybe_umount_usr_overlay' EXIT

enable_debug() {
    mkdir -p /run/systemd/system/systemd-localed.service.d
    cat >>/run/systemd/system/systemd-localed.service.d/override.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

    mkdir -p /run/systemd/system/systemd-vconsole-setup.service.d
    cat >>/run/systemd/system/systemd-vconsole-setup.service.d/override.conf <<EOF
[Unit]
StartLimitIntervalSec=0

[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF

    systemctl daemon-reload
}

restore_locale() {
    if [[ -d /usr/lib/locale/xx_XX.UTF-8 ]]; then
        rmdir /usr/lib/locale/xx_XX.UTF-8
    fi

    if [[ -f /tmp/locale.conf.bak ]]; then
        mv /tmp/locale.conf.bak /etc/locale.conf
    else
        rm -f /etc/locale.conf
    fi

    if [[ -f /tmp/default-locale.bak ]]; then
        mv /tmp/default-locale.bak /etc/default/locale
    else
        rm -f /etc/default/locale
        rmdir --ignore-fail-on-non-empty /etc/default
    fi

    if [[ -f /tmp/locale.gen.bak ]]; then
        mv /tmp/locale.gen.bak /etc/locale.gen
    else
        rm -f /etc/locale.gen
    fi
}

testcase_locale() {
    local i output

    if [[ -f /etc/locale.conf ]]; then
        cp /etc/locale.conf /tmp/locale.conf.bak
    fi

    # Debian/Ubuntu specific file
    if [[ -f /etc/default/locale ]]; then
        cp /etc/default/locale /tmp/default-locale.bak
    fi

    if [[ -f /etc/locale.gen ]]; then
        cp /etc/locale.gen /tmp/locale.gen.bak
    fi

    # remove locale.conf to make /etc/default/locale used by Debian/Ubuntu
    rm -f /etc/locale.conf
    # also remove /etc/default/locale
    rm -f /etc/default/locale
    # and create /etc/default to make /etc/default/locale created by localed
    mkdir -p /etc/default

    trap restore_locale RETURN

    if command -v locale-gen >/dev/null 2>&1 &&
           ! localectl list-locales | grep -F "en_US.UTF-8"; then
        # ensure at least one utf8 locale exist
        echo "en_US.UTF-8 UTF-8" >/etc/locale.gen
        locale-gen en_US.UTF-8
    fi

    # create invalid locale
    mkdir -p /usr/lib/locale/xx_XX.UTF-8
    assert_not_in "xx_XX.UTF-8" "$(localectl list-locales)"

    if [[ -z "$(localectl list-locales)" ]]; then
        echo "No locale installed, skipping test."
        return
    fi

    # start with a known default environment and make sure to also give a
    # default value to LC_CTYPE= since we're about to also set/unset it. We
    # also reload PID1 configuration to make sure that PID1 environment itself
    # is updated as it's not always been the case.
    assert_rc 0 localectl set-locale "LANG=en_US.UTF-8" "LC_CTYPE=C"
    systemctl daemon-reload
    output=$(localectl)
    assert_in "System Locale: LANG=en_US.UTF-8" "$output"
    assert_in "LC_CTYPE=C" "$output"
    output=$(systemctl show-environment)
    assert_in "LANG=en_US.UTF-8" "$output"
    assert_in "LC_CTYPE=C" "$output"

    # warn when kernel command line has locale settings
    output=$(SYSTEMD_PROC_CMDLINE="locale.LANG=C.UTF-8 locale.LC_CTYPE=ja_JP.UTF-8" localectl 2>&1)
    assert_in "Warning:" "$output"
    assert_in "Command Line: LANG=C.UTF-8" "$output"
    assert_in "LC_CTYPE=ja_JP.UTF-8" "$output"
    assert_in "System Locale:" "$output"

    # change locale
    for i in $(localectl list-locales); do
        assert_rc 0 localectl set-locale "LANG=C" "LC_CTYPE=$i"
        if [[ -f /etc/default/locale ]]; then
            assert_eq "$(cat /etc/default/locale)" "LANG=C
LC_CTYPE=$i"
        else
            assert_eq "$(cat /etc/locale.conf)" "LANG=C
LC_CTYPE=$i"
        fi
        output=$(localectl)
        assert_in "System Locale: LANG=C" "$output"
        assert_in "LC_CTYPE=$i" "$output"
        output=$(systemctl show-environment)
        assert_in "LANG=C" "$output"
        assert_in "LC_CTYPE=$i" "$output"

        assert_rc 0 localectl set-locale "$i"
        if [[ -f /etc/default/locale ]]; then
            assert_eq "$(cat /etc/default/locale)" "LANG=$i"
        else
            assert_eq "$(cat /etc/locale.conf)" "LANG=$i"
        fi
        output=$(localectl)
        assert_in "System Locale: LANG=$i" "$output"
        assert_not_in "LC_CTYPE=" "$output"
        output=$(systemctl show-environment)
        assert_in "LANG=$i" "$output"
        assert_not_in "LC_CTYPE=" "$output"
    done

    # test if localed auto-runs locale-gen
    if command -v locale-gen >/dev/null 2>&1 &&
           ! localectl list-locales | grep -F "de_DE.UTF-8"; then

        # clear previous locale
        systemctl stop systemd-localed.service
        rm -f /etc/locale.conf /etc/default/locale

        # change locale
        assert_rc 0 localectl set-locale de_DE.UTF-8
        if [[ -f /etc/default/locale ]]; then
            assert_eq "$(cat /etc/default/locale)" "LANG=de_DE.UTF-8"
        else
            assert_eq "$(cat /etc/locale.conf)" "LANG=de_DE.UTF-8"
        fi
        assert_in "System Locale: LANG=de_DE.UTF-8" "$(localectl)"
        assert_in "LANG=de_DE.UTF-8" "$(systemctl show-environment)"

        # ensure tested locale exists and works now
        assert_in "de_DE.UTF-8" "$(localectl list-locales)"
    fi
}

backup_keymap() {
    if [[ -f /etc/vconsole.conf ]]; then
        cp /etc/vconsole.conf /tmp/vconsole.conf.bak
    fi

    if [[ -f /etc/X11/xorg.conf.d/00-keyboard.conf ]]; then
        cp /etc/X11/xorg.conf.d/00-keyboard.conf /tmp/00-keyboard.conf.bak
    fi

    # Debian/Ubuntu specific file
    if [[ -f /etc/default/keyboard ]]; then
        cp /etc/default/keyboard /tmp/default-keyboard.bak
    fi

    mkdir -p /etc/default
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

    if [[ -f /tmp/default-keyboard.bak ]]; then
        mv /tmp/default-keyboard.bak /etc/default/keyboard
    else
        rm -f /etc/default/keyboard
        rmdir --ignore-fail-on-non-empty /etc/default
    fi
}

wait_vconsole_setup() {
    local i ss
    for i in {1..20}; do
        (( i > 1 )) && sleep 0.5
        ss="$(systemctl --property SubState --value show systemd-vconsole-setup.service)"
        if [[ "$ss" == "exited" || "$ss" == "dead" || "$ss" == "condition" ]]; then
            return 0
        elif [[ "$ss" == "failed" ]]; then
            echo "WARNING: systemd-vconsole-setup.service failed, ignoring." >&2
            systemctl reset-failed systemd-vconsole-setup.service
            return 0
        fi
    done

    systemctl status systemd-vconsole-setup.service
    return 1
}

testcase_vc_keymap() {
    local i output vc

    if [[ -z "$(localectl list-keymaps)" ]]; then
        echo "No vconsole keymap installed, skipping test."
        return
    fi

    backup_keymap
    trap restore_keymap RETURN

    # should activate daemon and work
    assert_in "VC Keymap:" "$(localectl)"

    for i in $(localectl list-keymaps); do
        # clear previous conversion from VC -> X11 keymap
        systemctl stop systemd-localed.service
        wait_vconsole_setup
        rm -f /etc/vconsole.conf /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard

        # set VC keymap
        assert_rc 0 localectl set-keymap "$i"
        output=$(localectl)

        # check VC keymap
        vc=$(cat /etc/vconsole.conf)
        assert_in "KEYMAP=$i" "$vc"
        assert_in "VC Keymap: $i" "$output"

        # check VC -> X11 keymap conversion
        if [[ "$i" == "us" ]]; then
            assert_in "X11 Layout: us" "$output"
            assert_in "X11 Model: pc105\+inet" "$output"
            assert_not_in "X11 Variant:" "$output"
            assert_in "X11 Options: terminate:ctrl_alt_bksp" "$output"

            assert_in "XKBLAYOUT=us" "$vc"
            assert_in "XKBMODEL=pc105\+inet" "$vc"
            assert_not_in "XKBVARIANT" "$vc"
            assert_in "XKBOPTIONS=terminate:ctrl_alt_bksp" "$vc"
        elif [[ "$i" == "us-acentos" ]]; then
            assert_in "X11 Layout: us" "$output"
            assert_in "X11 Model: pc105" "$output"
            assert_in "X11 Variant: intl" "$output"
            assert_in "X11 Options: terminate:ctrl_alt_bksp" "$output"

            assert_in "XKBLAYOUT=us" "$vc"
            assert_in "XKBMODEL=pc105" "$vc"
            assert_in "XKBVARIANT=intl" "$vc"
            assert_in "XKBOPTIONS=terminate:ctrl_alt_bksp" "$vc"
        elif [[ "$i" =~ ^us-.* ]]; then
            assert_in "X11 Layout: us" "$output"
            assert_in "X11 Model: microsoftpro" "$output"
            assert_in "X11 Variant:" "$output"
            assert_in "X11 Options: terminate:ctrl_alt_bksp" "$output"

            assert_in "XKBLAYOUT=us" "$vc"
            assert_in "XKBMODEL=microsoftpro" "$vc"
            assert_in "XKBVARIANT=" "$vc"
            assert_in "XKBOPTIONS=terminate:ctrl_alt_bksp" "$vc"
        fi
    done

    # gets along without config file
    systemctl stop systemd-localed.service
    wait_vconsole_setup
    rm -f /etc/vconsole.conf
    assert_in "VC Keymap: .unset." "$(localectl)"
}

testcase_x11_keymap() {
    local output

    if [[ -z "$(localectl list-x11-keymap-layouts)" ]]; then
        echo "No x11 keymap installed, skipping test."
        return
    fi

    backup_keymap
    trap restore_keymap RETURN

    # should activate daemon and work
    assert_in "X11 Layout:" "$(localectl)"

    # set x11 keymap (layout, model, variant, options)
    assert_rc 0 localectl set-x11-keymap us pc105+inet intl terminate:ctrl_alt_bksp

    if [[ -f /etc/default/keyboard ]]; then
        assert_eq "$(cat /etc/default/keyboard)" "XKBLAYOUT=us
XKBMODEL=pc105+inet
XKBVARIANT=intl
XKBOPTIONS=terminate:ctrl_alt_bksp"
    else
        output=$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)
        assert_in 'Option "XkbLayout" "us"' "$output"
        assert_in 'Option "XkbModel" "pc105\+inet"' "$output"
        assert_in 'Option "XkbVariant" "intl"' "$output"
        assert_in 'Option "XkbOptions" "terminate:ctrl_alt_bksp"' "$output"

        output=$(cat /etc/vconsole.conf)
        assert_in 'XKBLAYOUT=us' "$output"
        assert_in 'XKBMODEL=pc105\+inet' "$output"
        assert_in 'XKBVARIANT=intl' "$output"
        assert_in 'XKBOPTIONS=terminate:ctrl_alt_bksp' "$output"
    fi

    output=$(localectl)
    assert_in "X11 Layout: us" "$output"
    assert_in "X11 Model: pc105\+inet" "$output"
    assert_in "X11 Variant: intl" "$output"
    assert_in "X11 Options: terminate:ctrl_alt_bksp" "$output"

    # Debian/Ubuntu patch is buggy, unspecified settings are not cleared
    rm -f /etc/default/keyboard

    # set x11 keymap (layout, model, variant)
    assert_rc 0 localectl set-x11-keymap us pc105+inet intl

    if [[ -f /etc/default/keyboard ]]; then
        assert_eq "$(cat /etc/default/keyboard)" "XKBLAYOUT=us
XKBMODEL=pc105+inet
XKBVARIANT=intl"
    else
        output=$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)
        assert_in 'Option "XkbLayout" "us"' "$output"
        assert_in 'Option "XkbModel" "pc105\+inet"' "$output"
        assert_in 'Option "XkbVariant" "intl"' "$output"
        assert_not_in 'Option "XkbOptions"' "$output"

        output=$(cat /etc/vconsole.conf)
        assert_in 'XKBLAYOUT=us' "$output"
        assert_in 'XKBMODEL=pc105\+inet' "$output"
        assert_in 'XKBVARIANT=intl' "$output"
        assert_not_in 'XKBOPTIONS' "$output"
    fi

    output=$(localectl)
    assert_in "X11 Layout: us" "$output"
    assert_in "X11 Model: pc105\+inet" "$output"
    assert_in "X11 Variant: intl" "$output"
    assert_not_in "X11 Options:" "$output"

    # Debian/Ubuntu patch is buggy, unspecified settings are not cleared
    rm -f /etc/default/keyboard

    # set x11 keymap (layout, model)
    assert_rc 0 localectl set-x11-keymap us pc105+inet

    if [[ -f /etc/default/keyboard ]]; then
        assert_eq "$(cat /etc/default/keyboard)" "XKBLAYOUT=us
XKBMODEL=pc105+inet"
    else
        output=$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)
        assert_in 'Option "XkbLayout" "us"' "$output"
        assert_in 'Option "XkbModel" "pc105\+inet"' "$output"
        assert_not_in 'Option "XkbVariant"' "$output"
        assert_not_in 'Option "XkbOptions"' "$output"

        output=$(cat /etc/vconsole.conf)
        assert_in 'XKBLAYOUT=us' "$output"
        assert_in 'XKBMODEL=pc105\+inet' "$output"
        assert_not_in 'XKBVARIANT' "$output"
        assert_not_in 'XKBOPTIONS' "$output"
    fi

    output=$(localectl)
    assert_in "X11 Layout: us" "$output"
    assert_in "X11 Model: pc105\+inet" "$output"
    assert_not_in "X11 Variant:" "$output"
    assert_not_in "X11 Options:" "$output"

    # Debian/Ubuntu patch is buggy, unspecified settings are not cleared
    rm -f /etc/default/keyboard

    # set x11 keymap (layout)
    assert_rc 0 localectl set-x11-keymap us

    if [[ -f /etc/default/keyboard ]]; then
        assert_eq "$(cat /etc/default/keyboard)" "XKBLAYOUT=us"
    else
        output=$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)
        assert_in 'Option "XkbLayout" "us"' "$output"
        assert_not_in 'Option "XkbModel"' "$output"
        assert_not_in 'Option "XkbVariant"' "$output"
        assert_not_in 'Option "XkbOptions"' "$output"

        output=$(cat /etc/vconsole.conf)
        assert_in 'XKBLAYOUT=us' "$output"
        assert_not_in 'XKBMODEL' "$output"
        assert_not_in 'XKBVARIANT' "$output"
        assert_not_in 'XKBOPTIONS' "$output"
    fi

    output=$(localectl)
    assert_in "X11 Layout: us" "$output"
    assert_not_in "X11 Model:" "$output"
    assert_not_in "X11 Variant:" "$output"
    assert_not_in "X11 Options:" "$output"

    # gets along without config file
    systemctl stop systemd-localed.service
    rm -f /etc/vconsole.conf /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard
    output=$(localectl)
    assert_in "X11 Layout: .unset." "$output"
    assert_not_in "X11 Model:" "$output"
    assert_not_in "X11 Variant:" "$output"
    assert_not_in "X11 Options:" "$output"
}

testcase_convert() {
    if [[ -z "$(localectl list-keymaps)" ]]; then
        echo "No vconsole keymap installed, skipping test."
        return
    fi

    if [[ -z "$(localectl list-x11-keymap-layouts)" ]]; then
        echo "No x11 keymap installed, skipping test."
        return
    fi

    backup_keymap
    trap restore_keymap RETURN

    # clear previous settings
    systemctl stop systemd-localed.service
    wait_vconsole_setup
    rm -f /etc/vconsole.conf /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard

    # set VC keymap without conversion
    assert_rc 0 localectl --no-convert set-keymap us
    output=$(localectl)

    # check VC keymap
    vc=$(cat /etc/vconsole.conf)
    assert_in "KEYMAP=us" "$vc"
    assert_in "VC Keymap: us" "$output"

    # check VC -> X11 keymap conversion (nothing set)
    assert_in     "X11 Layout: .unset."  "$output"
    assert_not_in "X11 Model:"           "$output"
    assert_not_in "X11 Variant:"         "$output"
    assert_not_in "X11 Options:"         "$output"

    assert_not_in "XKBLAYOUT="  "$vc"
    assert_not_in "XKBMODEL="   "$vc"
    assert_not_in "XKBVARIANT=" "$vc"
    assert_not_in "XKBOPTIONS=" "$vc"

    # set VC keymap with conversion
    assert_rc 0 localectl set-keymap us
    output=$(localectl)

    # check VC keymap
    vc=$(cat /etc/vconsole.conf)
    assert_in "KEYMAP=us" "$vc"
    assert_in "VC Keymap: us" "$output"

    # check VC -> X11 keymap conversion
    assert_in     "X11 Layout: us"                       "$output"
    assert_in     "X11 Model: pc105\+inet"               "$output"
    assert_not_in "X11 Variant:"                         "$output"
    assert_in     "X11 Options: terminate:ctrl_alt_bksp" "$output"

    assert_in     "XKBLAYOUT=us"                       "$vc"
    assert_in     "XKBMODEL=pc105\+inet"               "$vc"
    assert_not_in "XKBVARIANT"                         "$vc"
    assert_in     "XKBOPTIONS=terminate:ctrl_alt_bksp" "$vc"

    # clear previous settings
    systemctl stop systemd-localed.service
    wait_vconsole_setup
    rm -f /etc/vconsole.conf /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard

    # set x11 keymap (layout) without conversion
    assert_rc 0 localectl --no-convert set-x11-keymap us

    assert_not_in "KEYMAP=" "$(cat /etc/vconsole.conf)"
    assert_in "VC Keymap: .unset." "$(localectl)"

    if [[ -f /etc/default/keyboard ]]; then
        assert_eq "$(cat /etc/default/keyboard)" "XKBLAYOUT=us"
    else
        output=$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)
        assert_in     'Option "XkbLayout" "us"' "$output"
        assert_not_in 'Option "XkbModel"'       "$output"
        assert_not_in 'Option "XkbVariant"'     "$output"
        assert_not_in 'Option "XkbOptions"'     "$output"

        output=$(cat /etc/vconsole.conf)
        assert_in     'XKBLAYOUT=us' "$output"
        assert_not_in 'XKBMODEL='    "$output"
        assert_not_in 'XKBVARIANT='  "$output"
        assert_not_in 'XKBOPTIONS='  "$output"
    fi

    output=$(localectl)
    assert_in     "X11 Layout: us" "$output"
    assert_not_in "X11 Model:"     "$output"
    assert_not_in "X11 Variant:"   "$output"
    assert_not_in "X11 Options:"   "$output"

    # set x11 keymap (layout, model) with conversion
    assert_rc 0 localectl set-x11-keymap us

    assert_in "KEYMAP=us" "$(cat /etc/vconsole.conf)"
    assert_in "VC Keymap: us" "$(localectl)"

    if [[ -f /etc/default/keyboard ]]; then
        assert_eq "$(cat /etc/default/keyboard)" "XKBLAYOUT=us"
    else
        output=$(cat /etc/X11/xorg.conf.d/00-keyboard.conf)
        assert_in     'Option "XkbLayout" "us"' "$output"
        assert_not_in 'Option "XkbModel"'       "$output"
        assert_not_in 'Option "XkbVariant"'     "$output"
        assert_not_in 'Option "XkbOptions"'     "$output"

        output=$(cat /etc/vconsole.conf)
        assert_in     'XKBLAYOUT=us' "$output"
        assert_not_in 'XKBMODEL='    "$output"
        assert_not_in 'XKBVARIANT='  "$output"
        assert_not_in 'XKBOPTIONS='  "$output"
    fi

    output=$(localectl)
    assert_in     "X11 Layout: us" "$output"
    assert_not_in "X11 Model:"     "$output"
    assert_not_in "X11 Variant:"   "$output"
    assert_not_in "X11 Options:"   "$output"
}

testcase_validate() {
    if [[ -z "$(localectl list-keymaps)" ]]; then
        echo "No vconsole keymap installed, skipping test."
        return
    fi

    if [[ -z "$(localectl list-x11-keymap-layouts)" ]]; then
        echo "No x11 keymap installed, skipping test."
        return
    fi

    backup_keymap
    trap restore_keymap RETURN

    # clear previous settings
    systemctl stop systemd-localed.service
    wait_vconsole_setup
    rm -f /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard

    # create invalid configs
    cat >/etc/vconsole.conf <<EOF
KEYMAP=foobar
XKBLAYOUT=hogehoge
EOF

    # confirm that the invalid settings are not shown
    output=$(localectl)
    assert_in "VC Keymap: .unset."  "$output"
    if [[ "$output" =~ "X11 Layout: hogehoge" ]]; then
        # Debian/Ubuntu build systemd without xkbcommon.
        echo "systemd built without xkbcommon, skipping test."
        return
    fi
    assert_in "X11 Layout: .unset." "$output"

    # only update the virtual console keymap
    assert_rc 0 localectl --no-convert set-keymap us

    output=$(localectl)
    assert_in "VC Keymap: us"       "$output"
    assert_in "X11 Layout: .unset." "$output"

    output=$(cat /etc/vconsole.conf)
    assert_in     "KEYMAP=us"  "$output"
    assert_not_in "XKBLAYOUT=" "$output"

    # clear previous settings
    systemctl stop systemd-localed.service
    wait_vconsole_setup
    rm -f /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard

    # create invalid configs
    cat >/etc/vconsole.conf <<EOF
KEYMAP=foobar
XKBLAYOUT=hogehoge
EOF

    # confirm that the invalid settings are not shown
    output=$(localectl)
    assert_in "VC Keymap: .unset."  "$output"
    assert_in "X11 Layout: .unset." "$output"

    # only update the X11 keyboard layout
    assert_rc 0 localectl --no-convert set-x11-keymap us

    output=$(localectl)
    assert_in "VC Keymap: .unset."  "$output"
    assert_in "X11 Layout: us"      "$output"

    output=$(cat /etc/vconsole.conf)
    assert_not_in "KEYMAP="      "$output"
    assert_in     "XKBLAYOUT=us" "$output"

    # clear previous settings
    systemctl stop systemd-localed.service
    wait_vconsole_setup
    rm -f /etc/X11/xorg.conf.d/00-keyboard.conf /etc/default/keyboard

    # create invalid configs
    cat >/etc/vconsole.conf <<EOF
KEYMAP=foobar
XKBLAYOUT=hogehoge
EOF

    # update the virtual console keymap with conversion
    assert_rc 0 localectl set-keymap us

    output=$(localectl)
    assert_in "VC Keymap: us"  "$output"
    assert_in "X11 Layout: us" "$output"

    output=$(cat /etc/vconsole.conf)
    assert_in "KEYMAP=us"    "$output"
    assert_in "XKBLAYOUT=us" "$output"
}

locale_gen_cleanup() {
    # Some running apps might keep the mount point busy, hence the lazy unmount
    mountpoint -q /usr/lib/locale && umount --lazy /usr/lib/locale
    [[ -e /tmp/locale.gen.bak ]] && mv -f /tmp/locale.gen.bak /etc/locale.gen

    return 0
}

# Issue: https://github.com/systemd/systemd/pull/27179
testcase_locale_gen_leading_space() {
    if ! command -v locale-gen >/dev/null; then
        echo "No locale-gen support, skipping test."
        return 0
    fi

    [[ -e /etc/locale.gen ]] && cp -f /etc/locale.gen /tmp/locale.gen.bak
    trap locale_gen_cleanup RETURN
    # Overmount the existing locale-gen database with an empty directory
    # to force it to regenerate locales
    mount -t tmpfs tmpfs /usr/lib/locale

    {
        echo -e "en_US.UTF-8 UTF-8"
        echo -e " en_US.UTF-8 UTF-8"
        echo -e "\ten_US.UTF-8 UTF-8"
        echo -e " \t en_US.UTF-8 UTF-8 \t"
    } >/etc/locale.gen

    localectl set-locale de_DE.UTF-8
    localectl set-locale en_US.UTF-8
}

# Make sure the content of kbd-model-map is the one that the tests expect
# regardless of the version installed on the distro where the testsuite is
# running on.
export SYSTEMD_KBD_MODEL_MAP=/usr/lib/systemd/tests/testdata/test-keymap-util/kbd-model-map

enable_debug
run_testcases

touch /testok
