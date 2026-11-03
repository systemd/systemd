#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Usage: test-introspect-cli.sh BINARY…
#
# Smoke-test --introspect-cli of every BINARY, then check details of the introspection of specific
# tools. Tools which are not among the arguments, because they are not built in this configuration,
# are skipped.
[[ $# -gt 0 ]] || { echo "Usage: $0 BINARY…" >&2; exit 1; }

export SYSTEMD_PAGER=cat

# --introspect-cli itself is marked as experimental
export SYSTEMD_EXPERIMENTAL=1

command -v jq >/dev/null || { echo "jq is not available, skipping." >&2; exit 77; }

# Aliases are passed as the bare names of symlinks in the current directory, make them paths so that
# they are never looked up in $PATH. Also build a basename → path map for the checks of specific tools.
PROGRAMS=()
declare -A BIN
for b in "$@"; do
    [[ "$b" == */* ]] || b=./$b
    PROGRAMS+=("$b")
    BIN[${b##*/}]=$b
done
have() { [[ -n "${BIN[$1]:-}" ]]; }

# Nope out if the build does not support experimental options at all
if ! out=$("${PROGRAMS[0]}" --introspect-cli 2>&1); then
    if [[ "$out" == *"not supported in this build"* ]]; then
        echo "Experimental options are disabled in this build, skipping." >&2
        exit 77
    fi
    echo "$out" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The smoke test captures the introspection of each program once, the checks of specific tools below
# read the captured output instead of running the program again.
introspection() { cat "$WORK/$1.json"; }

# Options and verbs (nested command objects) share the "arguments" array of a command object.
JQ_DEFS='def opts: [.arguments[]? | select(.type == "option")];
         def verbs: [.arguments[]? | select(.type == "command")];'

# Keys we emit which are defined by the spec. Everything else must carry the vendor prefix.
JQ_SPEC_KEYS='"mediaType", "commands", "type", "id", "names", "versions", "features", "project",
              "documentation", "abstract", "postscript", "help", "synopsis", "arguments",
              "value", "valueName", "sections", "isDeprecated", "isExperimental"'

# A smoke test for the introspection code
for bin in "${PROGRAMS[@]}"; do
    name=${bin##*/}
    JSON="$WORK/$name.json"

    "$bin" --introspect-cli >"$JSON"
    jq -e '.mediaType == "application/vnd.uapi-group.cli-introspection"' "$JSON"
    # The name the tool was invoked as is one of the names of a command, as its main name or an alias
    jq -e --arg name "$name" 'any(.commands[]; any(.names[]; . == $name))' "$JSON"
    jq -e 'all(.commands[]; .type == "command" and .id == .names[0] and (.versions | type == "array") and
                            all(.arguments[]?;
                                (.type == "command" and .id == .names[0]) or
                                (.type == "option" and .id == (.names[-1] | ltrimstr("--") | ltrimstr("-")))))' \
        "$JSON"
    jq -e '[.. | objects | keys[]] | all(IN('"$JQ_SPEC_KEYS"') or startswith("x-systemd."))' "$JSON"
    jq -e "$JQ_DEFS"'
        any(.commands[]; [opts[].names[-1]] | contains(["--help", "--version", "--introspect-cli"]))' "$JSON"
    "$bin" --intro | grep -e --help

    # If the tool has a "help" verb, it must work too
    if jq -e --arg name "$name" "$JQ_DEFS"'
            any(.commands[]; any(.names[]; . == $name) and (verbs | any(.names[0] == "help")))' \
            "$JSON" >/dev/null; then
        # 'systemctl help' shows unit manuals
        [[ "$name" == systemctl ]] && continue

        # Those programs try to connect to the bus for 'help' too :(
        # TODO: fix it!
        # shellcheck disable=SC2076
        if ! [[ " hostnamectl importctl localectl loginctl machinectl timedatectl updatectl " =~ " $(basename "$BINARY") " ]]; then
            continue
        fi

        "$bin" help >/dev/null
    fi
done

# check verbs and multicall binaries
if have systemd-hwdb; then
    introspection systemd-hwdb | jq -e "$JQ_DEFS"'
            .commands[0] | verbs | map(.names[0]) | sort == ["help", "query", "update"]'
fi

if have kernel-install; then
    introspection kernel-install | jq -e \
            '[.commands[].names[0]] | sort == ["installkernel", "kernel-install"]'
fi

if have networkctl; then
    introspection networkctl | jq -e \
        '[.commands[].names[0]] | sort == ["networkctl", "systemd-networkd"]'
fi

if have resolvectl; then
    introspection resolvectl | jq -e \
        '[.commands[].names[0]] | sort == ["resolvconf", "resolvectl", "systemd-resolve"]'
fi

if have storagectl; then
    introspection storagectl | jq -e \
        '[.commands[].names[0]] | sort == ["mount.storage", "storagectl"]'
fi

if have systemd-clonesetup; then
    introspection systemd-clonesetup | jq -e "$JQ_DEFS"'
        .commands[0] | verbs | map(.names[0]) | sort == ["add", "remove"]'
fi

if have systemd-dissect; then
    introspection systemd-dissect | jq -e \
        '[.commands[].names[0]] | sort == ["mount.ddi", "systemd-dissect"]'
fi

# systemd-hostnamed does not support --system/--user: options from groups not listed by the
# command must be rejected as unknown and hidden from the introspection (option group filtering)
if have systemd-hostnamed; then
    (! "${BIN[systemd-hostnamed]}" --system 2>&1) | grep "unrecognized option" >/dev/null
    introspection systemd-hostnamed | jq -e "$JQ_DEFS"'
        all(.commands[]; all(opts[]; .names[-1] != "--system"))'
fi

introspection systemd-id128 | jq -e "$JQ_DEFS"'
    .commands[0] | verbs | map(.names[0]) | contains(["new", "machine-id", "show", "help"])'

# Details of the schema: verbs carry a one-line help and the section they are listed under,
# options carry the name of their value and their section, commands list their man pages
# and their synopsis lines, one array per line. Our extensions carry the "x-systemd." prefix.
introspection systemd-id128 | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "new") |
        .help == "Generate a new ID" and .sections == ["Commands"]'
introspection systemd-id128 | jq -e "$JQ_DEFS"'
    .commands[0] | opts[] | select(.names[-1] == "--json") |
        .id == "json" and .value == "yes" and .valueName == "FORMAT" and .sections == ["Options"]'
introspection systemd-id128 | jq -e "$JQ_DEFS"'
    .commands[0] | opts[] | select(.names[-1] == "-j") |
        .id == "j" and .value == "no" and (has("valueName") | not)'
introspection systemd-id128 | jq -e \
    '.commands[0].documentation == ["man:systemd-id128(1)"]'
introspection systemd-id128 | jq -e \
    '.commands[0] | has("isExperimental") | not'

# Commands marked as experimental say so
for i in systemd-measure systemd-pcrlock systemd-report systemd-sysupdate systemd-vmspawn; do
    have "$i" || continue
    introspection "$i" | jq -e --arg name "$i" \
        'any(.commands[]; .names[0] == $name and .isExperimental == true)'
done
introspection systemd-id128 | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "show") | .synopsis == [["[NAME|UUID]"]]'
introspection systemd-id128 | jq -e "$JQ_DEFS"'
    .commands[0] | verbs[] | select(.names[0] == "new") |
        (has("synopsis") | not) and ."x-systemd.maxArguments" == 1'

if have systemd-analyze; then
    introspection systemd-analyze | jq -e "$JQ_DEFS"'
        .commands[0] | verbs[] | select(.names[0] == "time") | .sections == ["Boot Analysis"]'
fi

if have systemd-nspawn; then
    introspection systemd-nspawn | jq -e \
        '.commands[0].synopsis == [["[PATH] [ARGUMENTS…]"]]'
fi

# udevadm's verbs carry their own options, reported recursively
introspection udevadm | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] | select(.names[0] == "info") |
        [opts[].names[-1]] | contains(["--query", "--json", "--no-pager"])'

introspection udevadm | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] |
        select(.names[0] == "hwdb") | .isDeprecated == true'

# udevadm lock has multiple argspecs. Check that we print them.
"${BIN[udevadm]}" lock -h | grep -E '^> udevadm .* lock .* COMMAND$'
"${BIN[udevadm]}" lock -h | grep -E '^> udevadm .* lock .* --print$'
introspection udevadm | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "udevadm") | verbs[] | select(.names[0] == "lock") |
        .synopsis == [["COMMAND"], ["--print"]]'

# udevadm is also systemd-udevd
introspection udevadm | jq -e \
    '[.commands[].names[0]] | sort == ["systemd-udevd", "udevadm"]'

# The systemd-udevd command must own no verbs: the help-verb check in the loop above relies on
# this to never run 'systemd-udevd help', which would start the daemon.
introspection udevadm | jq -e "$JQ_DEFS"'
    .commands[] | select(.names[0] == "systemd-udevd") | verbs == []'

# Each subcommand's help and introspection must work
for v in cat control hwdb info lock monitor settle test test-builtin trigger verify wait; do
    "${BIN[udevadm]}" "$v" --help >/dev/null

    # TODO: fix this too
    "${BIN[udevadm]}" "$v" --help |& grep 'Running in chroot' && continue

    "${BIN[udevadm]}" "$v" --introspect-cli | jq -e \
        '.mediaType == "application/vnd.uapi-group.cli-introspection"'
done

# systemd is optionally a multicall binary that also provides systemd-executor
if have systemd-executor && [[ "$(readlink "${BIN[systemd-executor]}" 2>/dev/null)" == systemd ]]; then
    introspection systemd | jq -e \
        '[.commands[].names[0]] | sort == ["systemd", "systemd-executor"]'
fi

if have systemd-fstab-generator; then
    introspection systemd-fstab-generator | jq -e \
        '[.commands[].names[0]] | sort == ["systemd-fstab-generator", "systemd-sysroot-fstab-check"]'

    # The mode is picked by a substring match on argv[0], and the help must describe that mode
    (exec -a systemd-sysroot-fstab-check.real "${BIN[systemd-fstab-generator]}" --help) |
        grep -e '^> systemd-sysroot-fstab-check.real \[OPTION…\]$' >/dev/null
fi

if have systemd-mount; then
    introspection systemd-mount | jq -e \
        '[.commands[].names[0]] | sort == ["systemd-mount", "systemd-umount"]'

    # --tmpfs is only valid for systemd-mount
    (! "${BIN[systemd-mount]}" --tmpfs 2>&1) | grep "one argument required" >/dev/null
    (! "${BIN[systemd-umount]}" --tmpfs 2>&1) | grep "unrecognized option" >/dev/null
fi

if have systemd-mstack; then
    introspection systemd-mstack | jq -e \
        '[.commands[].names[0]] | sort == ["mount.mstack", "systemd-mstack"]'
fi

introspection systemd-run | jq -e \
    '[.commands[].names[0]] | sort == ["run0", "systemd-run"]'

if have systemd-sysext; then
    introspection systemd-sysext | jq -e \
        '[.commands[].names[0]] | sort == ["systemd-confext", "systemd-sysext"]'

    introspection systemd-sysext | jq -e "$JQ_DEFS"'
        .commands[0] | verbs | map(.names[0]) | contains(["status", "merge", "unmerge"])'
    introspection systemd-confext | jq -e "$JQ_DEFS"'
        .commands[0] | verbs | map(.names[0]) | contains(["status", "merge", "unmerge"])'
fi

introspection systemctl | jq -e \
    '[.commands[].names[0]] | sort == ["halt", "poweroff", "reboot", "shutdown", "systemctl"]'
