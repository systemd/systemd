#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Some commands are in $PATH, others are in our private directory.
# Check the other location too.
PATH=$PATH:/usr/lib/systemd

export SYSTEMD_PAGER=cat

# A smoke test for the introspection code
INTROSPECTABLE=(
    busctl
    coredumpctl
    homectl
    resolvectl
    systemd-ac-power
    systemd-analyze
    systemd-ask-password
    systemd-backlight
    systemd-battery-check
    systemd-binfmt
    systemd-bless-boot
    systemd-boot-check-no-failures
    systemd-bsod
    systemd-cat
    systemd-cgls
    systemd-cgtop
    systemd-clonesetup
    systemd-creds
    systemd-delta
    systemd-detect-virt
    systemd-dissect
    systemd-escape
    systemd-firstboot
    systemd-growfs
    systemd-hibernate-resume
    systemd-hwdb
    systemd-id128
    systemd-imds
    systemd-inhibit
    systemd-journal-gatewayd
    systemd-journal-remote
    systemd-journal-upload
    systemd-modules-load
    systemd-mute-console
    systemd-network-generator
    systemd-networkd-wait-online
    systemd-notify
    systemd-oomd
    systemd-path
    systemd-pcrextend
    systemd-pty-forward
    systemd-socket-activate
    systemd-socket-proxyd
    systemd-stdio-bridge
    systemd-storage-block
    systemd-storage-fs
    systemd-storagetm
    systemd-sysinstall
    systemd-tpm2-clear
    systemd-tpm2-setup
    systemd-tty-ask-password-agent
    systemd-update-done
    systemd-validatefs
    systemd-veritysetup
    timedatectl
    varlinkctl
)

for i in "${INTROSPECTABLE[@]}"; do
    command -v "$i" >/dev/null || continue

    $i --help >/dev/null

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
            '.commands[0].verbs | map(.names[0]) | sort == ["help", "query", "update"]'
fi

# systemd-id128 defines many verbs, check that some are described
systemd-id128 --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

# systemd-clonesetup defines verbs, check that they are described
systemd-clonesetup --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | sort == ["add", "remove"]'

# resolvectl is a multicall binary, check that both commands are described
resolvectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'
