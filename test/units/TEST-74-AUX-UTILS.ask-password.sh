#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e
    systemctl stop waldo-ask-pw-agent.service
}

trap at_exit EXIT

systemd-ask-password --help
systemd-tty-ask-password-agent --list

varlinkctl introspect /run/systemd/io.systemd.AskPassword

# Spawn an agent that always replies all ask password requests with "waldo"
systemd-run -u waldo-ask-pw-agent.service -p Environment=SYSTEMD_ASK_PASSWORD_AGENT_PASSWORD=waldo -p Type=notify /usr/bin/systemd-tty-ask-password-agent --watch --console=/dev/console
assert_eq "$(systemd-ask-password --no-tty)" "waldo"
assert_eq "$(varlinkctl call /usr/bin/systemd-ask-password io.systemd.AskPassword.Ask '{"message":"foobar"}' | jq '.passwords[0]')" "\"waldo\""
