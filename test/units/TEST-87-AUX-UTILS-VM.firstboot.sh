#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 77
fi

at_exit() {
    if [[ -d /run/systemd/system/systemd-firstboot.service.d ]]; then
        rm -rf /run/systemd/system/systemd-firstboot.service.d
        systemctl daemon-reload
        systemctl reset-failed systemd-firstboot.service
    fi
    if findmnt /sys/class/tty/console/active >/dev/null; then
        umount /sys/class/tty/console/active
    fi
    [[ -n "${ACTIVE_CONSOLE:-}" ]] && rm -f "$ACTIVE_CONSOLE"
    [[ -n "${JOURNAL_CURSOR:-}" ]] && rm -f "$JOURNAL_CURSOR"
    [[ -n "${WETC:-}" ]] && rm -rf "$WETC"
}

trap at_exit EXIT

# Simulate a system without a usable console (see TEST-87-AUX-UTILS-VM.tty-graceful.sh), so that
# StandardInput=tty-graceful connects systemd-firstboot.service's stdin to /dev/null. Redirect the settings
# away from the host's /etc.
ACTIVE_CONSOLE="$(mktemp)"
mount --bind "$ACTIVE_CONSOLE" /sys/class/tty/console/active
WETC="$(mktemp -d)"
mkdir -p /run/systemd/system/systemd-firstboot.service.d

firstboot_unit_dropin() {
    local cmdline="${1:?}" credential="${2:-}"

    cat >/run/systemd/system/systemd-firstboot.service.d/50-test.conf <<EOF
[Unit]
ConditionFirstBoot=

[Service]
# mkosi.conf boots with systemd.firstboot=no
Environment=SYSTEMD_PROC_CMDLINE=$cmdline
Environment=SYSTEMD_ETC_LOCALTIME=$WETC/localtime SYSTEMD_ETC_LOCALE_CONF=$WETC/locale.conf SYSTEMD_ETC_VCONSOLE_CONF=$WETC/vconsole.conf
# Don't let system credentials (e.g. from mkosi) take precedence
ImportCredential=
$credential
EOF
    systemctl daemon-reload
}

# systemd-firstboot exits too quickly for journald to reliably associate its messages with the unit, so
# match by identifier, bounded by a cursor
JOURNAL_CURSOR="$(mktemp)"
journalctl -n 0 --cursor-file="$JOURNAL_CURSOR"

# Without systemd.firstboot=, stdin on /dev/null implies headless mode, so credentials still get applied
firstboot_unit_dropin "quiet" "SetCredential=firstboot.timezone:Europe/Berlin"
systemctl restart systemd-firstboot.service
[[ "$(readlink "$WETC/localtime")" =~ /Europe/Berlin$ ]]
journalctl --sync
journalctl --cursor-file="$JOURNAL_CURSOR" SYSLOG_IDENTIFIER=systemd-firstboot \
           --grep "Standard input is /dev/null, skipping interactive prompts"

# An explicit systemd.firstboot=yes still prompts, which fails without a console. Remove the timezone so that
# there's always something to prompt for.
rm "$WETC/localtime"
firstboot_unit_dropin "systemd.firstboot=yes"
(! systemctl restart systemd-firstboot.service)
journalctl --sync
journalctl --cursor-file="$JOURNAL_CURSOR" SYSLOG_IDENTIFIER=systemd-firstboot \
           --grep "Failed to query user: Input/output error"
