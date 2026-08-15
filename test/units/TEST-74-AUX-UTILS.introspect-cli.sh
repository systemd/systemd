#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Just a smoke test for the introspection code
for i in systemd-ac-power systemd-analyze systemd-ask-password systemd-dissect \
         systemd-id128 systemd-notify homectl resolvectl timedatectl varlinkctl; do
    command -v "$i" >/dev/null || continue

    $i --introspect-cli | jq -e \
        '.mediaType == "application/vnd.io.systemd.cli-introspection-0"'
    $i --introspect-cli | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name)'
    $i --introspect-cli | jq -e \
        'any(.commands[]; [.options[].names[-1]] | contains(["--help", "--version", "--introspect-cli"]))'
    $i --intro | grep -e --help
done

# Those are not in $PATH and do not do regular option parsing, so the option must
# be given verbatim
for i in /usr/lib/systemd/systemd-backlight /usr/lib/systemd/systemd-veritysetup; do
    [[ -x "$i" ]] || continue

    $i --introspect-cli | jq -e \
        '.mediaType == "application/vnd.io.systemd.cli-introspection-0"'
done

# systemd-id128 defines verbs, check that they are described
systemd-id128 --introspect-cli | jq -e \
    '.commands[0].verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

# resolvectl is a multicall binary, check that both commands are described
resolvectl --introspect-cli | jq -e \
    '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'
