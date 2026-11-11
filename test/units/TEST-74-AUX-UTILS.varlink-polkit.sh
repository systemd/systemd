#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Varlink authorization needs pidfd subjects (kernel >= 6.5 and polkit >= 124).
if [[ ! -f /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service ]] ||
   [[ ! -f /usr/share/polkit-1/actions/org.freedesktop.hostname1.policy ]] ||
   ! systemd-analyze compare-versions "$(uname -r)" ge 6.5 ||
   ! systemd-analyze compare-versions "$(pkcheck --version | awk '{print $3}')" ge 124; then
    echo 'Polkit with pidfd support is required, skipping test.'
    exit 77
fi

cleanup() {
    rm -f /etc/polkit-1/rules.d/00-varlink-oneway-test.rules
    systemctl try-reload-or-restart polkit.service
}
trap cleanup EXIT

mkdir -p /etc/polkit-1/rules.d
cat >/etc/polkit-1/rules.d/00-varlink-oneway-test.rules <<'RULE'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.hostname1.get-hardware-serial" && subject.user == "testuser") {
        polkit.spawn(["/usr/bin/sleep", "3"]);
        return polkit.Result.YES;
    }
});
RULE
systemctl reload-or-restart polkit.service
systemctl start systemd-hostnamed.service systemd-hostnamed.socket

# Verify that ordinary asynchronous authorization succeeds and the delay rule is active.
start=$SECONDS
runas testuser timeout 15 varlinkctl --json=short call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}' |
    grep '"Hostname":' >/dev/null
(( SECONDS - start >= 3 ))

systemctl is-active systemd-hostnamed.service
request='{"method":"io.systemd.Hostname.Describe","parameters":{},"oneway":true}'
probe='{"method":"org.varlink.service.GetInfo","parameters":{}}'
printf '%s\0' "$request" "$request" "$probe" |
    runas testuser socat -t 10 - UNIX-CONNECT:/run/systemd/io.systemd.Hostname |
    grep -a '"vendor":'
systemctl is-active systemd-hostnamed.service
