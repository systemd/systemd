#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Some commands are in $PATH, others are in our private directory.
# Check the other location too.
PATH=$PATH:/usr/lib/systemd

# A smoke test for the introspection code
INTROSPECTABLE=(
    homectl
    resolvectl
    systemd-ac-power
    systemd-analyze
    systemd-ask-password
    systemd-backlight
    systemd-battery-check
    systemd-binfmt
    systemd-bsod
    systemd-cat
    systemd-cgls
    systemd-cgtop
    systemd-delta
    systemd-detect-virt
    systemd-dissect
    systemd-escape
    systemd-firstboot
    systemd-hwdb
    systemd-id128
    systemd-imds
    systemd-inhibit
    systemd-mute-console
    systemd-notify
    systemd-oomd
    systemd-path
    systemd-pty-forward
    systemd-socket-activate
    systemd-tty-ask-password-agent
    systemd-veritysetup
    timedatectl
    varlinkctl
)

for i in "${INTROSPECTABLE[@]}"; do
    command -v "$i" >/dev/null || continue

    SYSTEMD_PAGER=cat $i --help >/dev/null

    $i --introspect-cli | jq -e \
        '.mediaType == "application/vnd.io.systemd.cli-introspection-0"'
    $i --introspect-cli | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name)'
    $i --introspect-cli | jq -e \
        'any(.commands[]; [.options[].names[-1]] | contains(["--help", "--version", "--introspect-cli"]))'
    $i --intro | grep -e --help
done

# systemd-hwdb defines verbs, check that they are described
if command -v systemd-hwdb >/dev/null; then
    systemd-hwdb --introspect-cli | jq -e \
            '.commands[0].verbs | map(.names[0]) | contains(["query", "update"])'
fi

# systemd-id128 defines verbs, check that they are described
systemd-id128 --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

# resolvectl is a multicall binary, check that both commands are described
resolvectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'
