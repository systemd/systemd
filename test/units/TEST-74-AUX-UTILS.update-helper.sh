#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

HELPER=/usr/lib/systemd/systemd-update-helper
PRIVATE=/run/user/4711/systemd/private

at_exit() {
    set +e

    systemctl thaw user@4711.service
    if [[ -e "$PRIVATE.real" ]]; then
        rm -f "$PRIVATE"
        mv "$PRIVATE.real" "$PRIVATE"
    fi
    systemctl stop update-helper-test.service 'update-helper-test@*.service' update-helper-victim.service
    loginctl disable-linger testuser
    rm -f /etc/systemd/system/update-helper-test.service \
          /etc/systemd/system/update-helper-test@.service \
          /run/systemd/system/update-helper-victim.service \
          /etc/systemd/system-preset/00-update-helper-test.preset \
          /etc/systemd/user/update-helper-test.service \
          /etc/systemd/user-preset/00-update-helper-test.preset \
          /etc/systemd/user/default.target.wants/update-helper-test.service \
          /home/testuser/.config/systemd/user/default.target.wants/update-helper-test.service
    systemctl daemon-reload
}

trap at_exit EXIT

user_systemctl() {
    systemctl --user --machine=testuser@ "$@"
}

: "The help output lists every command once"
[[ "$("$HELPER" --help | grep -c '^ *install-units')" -eq 1 ]]

: "Commands with a fixed scope refuse a scope option"
(! "$HELPER" --global install-system-units update-helper-test.service)
(! "$HELPER" --system remove-user-units update-helper-test.service)

: "System units"
cat >/etc/systemd/system/update-helper-test.service <<EOF
[Service]
ExecStart=sleep infinity

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/update-helper-test@.service <<EOF
[Service]
ExecStart=sleep infinity

[Install]
WantedBy=multi-user.target
EOF
mkdir -p /etc/systemd/system-preset
echo "enable update-helper-test.service" >/etc/systemd/system-preset/00-update-helper-test.preset
systemctl daemon-reload

"$HELPER" --dry-run install-system-units update-helper-test.service
[[ "$(systemctl is-enabled update-helper-test.service)" == disabled ]]
"$HELPER" install-system-units update-helper-test.service
[[ "$(systemctl is-enabled update-helper-test.service)" == enabled ]]

systemctl start update-helper-test.service update-helper-test@a.service update-helper-test@b.service
id="$(systemctl show -P InvocationID update-helper-test.service)"
id_a="$(systemctl show -P InvocationID update-helper-test@a.service)"
id_b="$(systemctl show -P InvocationID update-helper-test@b.service)"

"$HELPER" mark-restart-system-units update-helper-test.service update-helper-test@.service
[[ "$(systemctl show -P Markers update-helper-test.service)" == needs-restart ]]
[[ "$(systemctl show -P Markers update-helper-test@a.service)" == needs-restart ]]
[[ "$(systemctl show -P Markers update-helper-test@b.service)" == needs-restart ]]
"$HELPER" system-restart
[[ "$(systemctl show -P InvocationID update-helper-test.service)" != "$id" ]]
[[ "$(systemctl show -P InvocationID update-helper-test@a.service)" != "$id_a" ]]
[[ "$(systemctl show -P InvocationID update-helper-test@b.service)" != "$id_b" ]]

"$HELPER" --dry-run remove-system-units update-helper-test.service update-helper-test@.service
[[ "$(systemctl is-enabled update-helper-test.service)" == enabled ]]
systemctl is-active update-helper-test.service update-helper-test@a.service update-helper-test@b.service

printf '%s\n' /etc/systemd/system/update-helper-test.service /etc/systemd/system/update-helper-test@.service /etc/passwd |
    "$HELPER" --stdin remove-units
[[ "$(systemctl is-enabled update-helper-test.service)" == disabled ]]
(! systemctl is-active update-helper-test.service)
(! systemctl is-active update-helper-test@a.service)
(! systemctl is-active update-helper-test@b.service)

: "User units"
cat >/etc/systemd/user/update-helper-test.service <<EOF
[Service]
ExecStart=sleep infinity

[Install]
WantedBy=default.target
EOF
mkdir -p /etc/systemd/user-preset
echo "enable update-helper-test.service" >/etc/systemd/user-preset/00-update-helper-test.preset

loginctl enable-linger testuser
timeout 30 bash -c 'until systemctl is-active user@4711.service; do sleep .5; done'

"$HELPER" user-reload

"$HELPER" install-user-units update-helper-test.service
test -L /etc/systemd/user/default.target.wants/update-helper-test.service

user_systemctl start update-helper-test.service
id="$(user_systemctl show -P InvocationID update-helper-test.service)"
"$HELPER" mark-restart-user-units update-helper-test.service
[[ "$(user_systemctl show -P Markers update-helper-test.service)" == needs-restart ]]
"$HELPER" user-restart
[[ "$(user_systemctl show -P InvocationID update-helper-test.service)" != "$id" ]]

# Removing user units also disables them in the configuration of each user.
run0 -u testuser systemctl --user enable update-helper-test.service
test -L /home/testuser/.config/systemd/user/default.target.wants/update-helper-test.service
"$HELPER" remove-user-units update-helper-test.service
test ! -e /etc/systemd/user/default.target.wants/update-helper-test.service
test ! -L /home/testuser/.config/systemd/user/default.target.wants/update-helper-test.service
(! user_systemctl is-active update-helper-test.service)

: "A symlink in place of the private socket of a user manager is refused"
cat >/run/systemd/system/update-helper-victim.service <<EOF
[Service]
ExecStart=sleep infinity
EOF
systemctl daemon-reload
systemctl start update-helper-victim.service
mv "$PRIVATE" "$PRIVATE.real"
ln -s /run/systemd/private "$PRIVATE"
"$HELPER" remove-user-units update-helper-victim.service
systemctl is-active update-helper-victim.service
rm "$PRIVATE"
mv "$PRIVATE.real" "$PRIVATE"

: "A frozen user manager does not block the helper"
user_systemctl start update-helper-test.service
systemctl freeze user@4711.service
timeout 60 "$HELPER" mark-restart-user-units update-helper-test.service
timeout 60 "$HELPER" user-restart
timeout 60 "$HELPER" remove-user-units update-helper-test.service
systemctl thaw user@4711.service
