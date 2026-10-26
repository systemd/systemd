#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

SFTP_SERVER="$(systemctl cat varlink-sftp-root.service 2>/dev/null | sed -n 's/^ConditionPathExists=//p')" || :
if [[ ! -x "$SFTP_SERVER" ]] || ! command -v sftp >/dev/null; then
    echo "sftp-server or sftp not available, skipping." >&2
    exit 77
fi

TMPDIR_SFTP="$(mktemp -d)"

at_exit() {
    set +e
    systemctl stop varlink-sftp-root.socket varlink-sftp-root-ro.socket varlink-sftp-root.service varlink-sftp-root-ro.service
    rm -rf "$TMPDIR_SFTP"
}
trap at_exit EXIT

sftp_varlink() {
    sftp -b - -D "varlinkctl call --upgrade /run/varlink/registry/$1 $1.Connect"
}

systemctl start varlink-sftp-root.socket varlink-sftp-root-ro.socket
echo hello >"$TMPDIR_SFTP/src"

(! sftp_varlink io.systemd.Sftp.RootReadOnly <<<"put $TMPDIR_SFTP/src $TMPDIR_SFTP/ro")
test ! -e "$TMPDIR_SFTP/ro"
sftp_varlink io.systemd.Sftp.RootReadOnly <<<"get $TMPDIR_SFTP/src $TMPDIR_SFTP/ro-get"
cmp "$TMPDIR_SFTP/src" "$TMPDIR_SFTP/ro-get"

sftp_varlink io.systemd.Sftp.Root <<<"put $TMPDIR_SFTP/src $TMPDIR_SFTP/rw"
cmp "$TMPDIR_SFTP/src" "$TMPDIR_SFTP/rw"
