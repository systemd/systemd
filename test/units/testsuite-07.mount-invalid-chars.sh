#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Don't send invalid characters over dbus if a mount contains them

at_exit() {
    mountpoint -q /proc/1/mountinfo && umount /proc/1/mountinfo
    [[ -e /tmp/fstab.bak ]] && mv -f /tmp/fstab /etc/fstab
    rm -f /run/systemd/system/foo-*.mount
    systemctl daemon-reload
}

trap at_exit EXIT

# Check invalid characters directly in /proc/mountinfo
#
# This is a bit tricky (and hacky), since we have to temporarily replace
# PID 1's /proc/mountinfo, but we have to keep the original mounts intact,
# otherwise systemd would unmount them on reload
TMP_MOUNTINFO="$(mktemp)"

cp /proc/1/mountinfo "$TMP_MOUNTINFO"
# Add a mount entry with a "Unicode non-character" in it
echo -ne '69 1 252:2 / /foo/mountinfo rw,relatime shared:1 - cifs //foo\ufffebar rw,seclabel\n' >>"$TMP_MOUNTINFO"
mount --bind "$TMP_MOUNTINFO" /proc/1/mountinfo
systemctl daemon-reload
# On affected versions this would throw an error:
#   Failed to get properties: Bad message
systemctl status foo-mountinfo.mount

umount /proc/1/mountinfo
systemctl daemon-reload
rm -f "$TMP_MOUNTINFO"

# Check invalid characters in a mount unit
#
# systemd already handles this and refuses to load the invalid string, e.g.:
#   foo-fstab.mount:9: String is not UTF-8 clean, ignoring assignment: What=//localhost/foo���bar
#
# a) Unit generated from /etc/fstab
[[ -e /etc/fstab ]] && cp -f /etc/fstab /tmp/fstab.bak

echo -ne '//localhost/foo\ufffebar  /foo/fstab  cifs defaults 0 0\n' >/etc/fstab
systemctl daemon-reload
[[ "$(systemctl show -P UnitFileState foo-fstab.mount)" == bad ]]

# b) Unit generated from /etc/fstab (but the invalid character is in options)
echo -ne '//localhost/foobar  /foo/fstab/opt  cifs nosuid,a\ufffeb,noexec 0 0\n' >/etc/fstab
systemctl daemon-reload
[[ "$(systemctl show -P UnitFileState foo-fstab-opt.mount)" == bad ]]
rm -f /etc/fstab

[[ -e /tmp/fstab.bak ]] && mv -f /tmp/fstab /etc/fstab
systemctl daemon-reload

# c) Mount unit
mkdir -p /run/systemd/system
echo -ne '[Mount]\nWhat=//localhost/foo\ufffebar\nWhere=/foo/unit\nType=cifs\nOptions=noexec\n' >/run/systemd/system/foo-unit.mount
systemctl daemon-reload
[[ "$(systemctl show -P UnitFileState foo-unit.mount)" == bad ]]
rm -f /run/systemd/system/foo-unit.mount

# d) Mount unit (but the invalid character is in Options=)
mkdir -p /run/systemd/system
echo -ne '[Mount]\nWhat=//localhost/foobar\nWhere=/foo/unit/opt\nType=cifs\nOptions=noexec,a\ufffeb,nosuid\n' >/run/systemd/system/foo-unit-opt.mount
systemctl daemon-reload
[[ "$(systemctl show -P UnitFileState foo-unit-opt.mount)" == bad ]]
rm -f /run/systemd/system/foo-unit-opt.mount
