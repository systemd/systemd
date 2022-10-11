#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

SOURCE_ROOT="${1:?}"
BUILD_ROOT="${2:?}"
OUTPUT_ROOT="${3:?}"

command -v gawk &>/dev/null || exit 77

function generate_directives() {
    gawk -v sec_rx="${2:-""}" -v unit_type="${3:-""}" '
    match($0, /^([^ \t\.]+)\.([^ \t\.,]+)/, m) {
        # res[section][directive] = 1
        res[m[1]][m[2]] = 1;
    }
    END {
        if (unit_type)
            print unit_type

        for (section in res) {
            if (sec_rx && section !~ sec_rx)
                continue

            print "[" section "]";
            for (directive in res[section]) {
                print directive "=";
            }
        }
    }
    ' "$1"
}

out="$OUTPUT_ROOT/fuzz-network-parser/directives"
mkdir -p "$(dirname "$out")"
generate_directives "$SOURCE_ROOT"/src/network/networkd-network-gperf.gperf | sort >"$out"

out="$OUTPUT_ROOT/fuzz-netdev-parser/directives.netdev"
mkdir -p "$(dirname "$out")"
generate_directives "$SOURCE_ROOT"/src/network/netdev/netdev-gperf.gperf | sort >"$out"

out="$OUTPUT_ROOT/fuzz-link-parser/directives.link"
mkdir -p "$(dirname "$out")"
generate_directives "$SOURCE_ROOT"/src/udev/net/link-config-gperf.gperf | sort >"$out"

for section in Automount Mount Path Scope Slice Socket Swap Timer; do
    out="$OUTPUT_ROOT/fuzz-unit-file/directives.${section,,}"
    mkdir -p "$(dirname "$out")"
    generate_directives "$BUILD_ROOT"/src/core/load-fragment-gperf.gperf "$section" "${section,,}" | sort >"$out"
done

out="$OUTPUT_ROOT/fuzz-unit-file/directives.service"
mkdir -p "$(dirname "$out")"
generate_directives "$BUILD_ROOT"/src/core/load-fragment-gperf.gperf "(Service|Unit|Install)" "service" | sort >"$out"
