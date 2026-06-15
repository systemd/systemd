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
    if [[ -e /etc/polkit-1/rules.d/varlink-sftp-test.rules ]]; then
        rm -f /etc/polkit-1/rules.d/varlink-sftp-test.rules
        systemctl try-reload-or-restart polkit.service
    fi
    rm -rf "$TMPDIR_SFTP"
}
trap at_exit EXIT

sftp_varlink() {
    sftp -b - -D "varlinkctl call --upgrade /run/varlink/registry/$1 $1.Connect"
}

sftp_varlink_testuser() {
    run0 --pipe -u testuser sftp -b - -D "varlinkctl call --upgrade /run/varlink/registry/$1 $1.Connect"
}

systemctl start varlink-sftp-root.socket varlink-sftp-root-ro.socket
chmod 755 "$TMPDIR_SFTP"
echo hello >"$TMPDIR_SFTP/src"

# Without a polkit rule an unprivileged user is denied on both endpoints
(! sftp_varlink_testuser io.systemd.Sftp.RootReadOnly <<<"get $TMPDIR_SFTP/src /tmp/varlink-sftp-denied")
test ! -e /tmp/varlink-sftp-denied

# Grant testuser read-only access only and verify the two actions are enforced independently.
# Varlink polkit checks only send a pidfd subject, which needs kernel >= 6.5 and polkit >= 124.
if [[ -f /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service ]] &&
   [[ -f /usr/share/polkit-1/actions/io.systemd.sftp.policy ]] &&
   systemd-analyze compare-versions "$(uname -r)" ge 6.5 &&
   systemd-analyze compare-versions "$(pkcheck --version | awk '{print $3}')" ge 124; then
    mkdir -p /etc/polkit-1/rules.d
    cat >/etc/polkit-1/rules.d/varlink-sftp-test.rules <<'EOF2'
polkit.addRule(function(action, subject) {
    if (action.id == "io.systemd.sftp.root-read-only" && subject.user == "testuser") {
        return polkit.Result.YES;
    }
});
EOF2
    systemctl try-reload-or-restart polkit.service

    sftp_varlink_testuser io.systemd.Sftp.RootReadOnly <<<"get $TMPDIR_SFTP/src /tmp/varlink-sftp-testuser-get"
    cmp "$TMPDIR_SFTP/src" /tmp/varlink-sftp-testuser-get
    rm -f /tmp/varlink-sftp-testuser-get
    (! sftp_varlink_testuser io.systemd.Sftp.Root <<<"put $TMPDIR_SFTP/src $TMPDIR_SFTP/testuser-rw")
    test ! -e "$TMPDIR_SFTP/testuser-rw"

    rm -f /etc/polkit-1/rules.d/varlink-sftp-test.rules
    systemctl try-reload-or-restart polkit.service
fi

(! sftp_varlink io.systemd.Sftp.RootReadOnly <<<"put $TMPDIR_SFTP/src $TMPDIR_SFTP/ro")
test ! -e "$TMPDIR_SFTP/ro"
sftp_varlink io.systemd.Sftp.RootReadOnly <<<"get $TMPDIR_SFTP/src $TMPDIR_SFTP/ro-get"
cmp "$TMPDIR_SFTP/src" "$TMPDIR_SFTP/ro-get"

sftp_varlink io.systemd.Sftp.Root <<<"put $TMPDIR_SFTP/src $TMPDIR_SFTP/rw"
cmp "$TMPDIR_SFTP/src" "$TMPDIR_SFTP/rw"
