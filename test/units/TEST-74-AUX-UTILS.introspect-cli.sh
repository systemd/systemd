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
    bootctl
    busctl
    coredumpctl
    homectl
    hostnamectl
    importctl
    journalctl
    localectl
    loginctl
    machinectl
    networkctl
    oomctl
    portablectl
    resolvectl
    run0
    storagectl
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
    systemd-cryptenroll
    systemd-cryptsetup
    systemd-delta
    systemd-detect-virt
    systemd-dissect
    systemd-escape
    systemd-factory-reset
    systemd-firstboot
    systemd-growfs
    systemd-hibernate-resume
    systemd-hwdb
    systemd-id128
    systemd-imds
    systemd-imdsd
    systemd-inhibit
    systemd-journal-gatewayd
    systemd-journal-remote
    systemd-journal-upload
    systemd-keyutil
    systemd-machine-id-setup
    systemd-measure
    systemd-modules-load
    systemd-mstack
    systemd-mute-console
    systemd-network-generator
    systemd-networkd-wait-online
    systemd-notify
    systemd-nspawn
    systemd-oomd
    systemd-path
    systemd-pcrextend
    systemd-pcrlock
    systemd-pty-forward
    systemd-random-seed
    systemd-repart
    systemd-report
    systemd-run
    systemd-sbsign
    systemd-sleep
    systemd-socket-activate
    systemd-socket-proxyd
    systemd-ssh-issue
    systemd-stdio-bridge
    systemd-storage-block
    systemd-storage-fs
    systemd-storagetm
    systemd-sysctl
    systemd-sysinstall
    systemd-sysupdate
    systemd-sysusers
    systemd-tmpfiles
    systemd-tpm2-clear
    systemd-tpm2-setup
    systemd-tty-ask-password-agent
    systemd-update-done
    systemd-validatefs
    systemd-veritysetup
    systemd-vmspawn
    systemd-vpick
    timedatectl
    updatectl
    userdbctl
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

    # If the tool has a "help" verb, it must work too
    if $i --introspect-cli | jq -e 'any(.commands[]; (.verbs // []) | any(.names[0] == "help"))' >/dev/null; then
        $i help >/dev/null
    fi
done

# check verbs and multicall binaries
if command -v systemd-hwdb >/dev/null; then
    systemd-hwdb --introspect-cli | jq -e \
            '.commands[0].verbs | map(.names[0]) | sort == ["help", "query", "update"]'
fi

resolvectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'

storagectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.storage", "storagectl"]'

systemd-clonesetup --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | sort == ["add", "remove"]'

systemd-dissect --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.ddi", "systemd-dissect"]'

systemd-id128 --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

systemd-mstack --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["mount.mstack", "systemd-mstack"]'

systemd-run --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["run0", "systemd-run"]'
