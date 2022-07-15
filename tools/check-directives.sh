#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

SOURCE_ROOT="${1:?}"
BUILD_ROOT="${2:?}"

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

ret=0
if ! diff \
     <(generate_directives "$SOURCE_ROOT"/src/network/networkd-network-gperf.gperf | sort) \
     <(sort "$SOURCE_ROOT"/test/fuzz/fuzz-network-parser/directives); then
    echo "Looks like test/fuzz/fuzz-network-parser/directives hasn't been updated"
    ret=1
fi

if ! diff \
     <(generate_directives "$SOURCE_ROOT"/src/network/netdev/netdev-gperf.gperf | sort) \
     <(sort "$SOURCE_ROOT"/test/fuzz/fuzz-netdev-parser/directives.netdev); then
    echo "Looks like test/fuzz/fuzz-netdev-parser/directives.netdev hasn't been updated"
    ret=1
fi

if ! diff \
     <(generate_directives "$SOURCE_ROOT"/src/udev/net/link-config-gperf.gperf | sort) \
     <(sort "$SOURCE_ROOT"/test/fuzz/fuzz-link-parser/directives.link) ; then
    echo "Looks like test/fuzz/fuzz-link-parser/directives.link hasn't been updated"
    ret=1
fi

for section in Automount Mount Path Scope Slice Socket Swap Timer; do
    if ! diff \
         <(generate_directives "$BUILD_ROOT"/src/core/load-fragment-gperf.gperf "$section" "${section,,}" | sort) \
         <(sort "$SOURCE_ROOT/test/fuzz/fuzz-unit-file/directives.${section,,}") ; then
        echo "Looks like test/fuzz/fuzz-unit-file/directives.${section,,} hasn't been updated"
        ret=1
    fi
done

if ! diff \
     <(generate_directives "$BUILD_ROOT"/src/core/load-fragment-gperf.gperf "(Service|Unit|Install)" "service" | sort) \
     <(sort "$SOURCE_ROOT/test/fuzz/fuzz-unit-file/directives.service") ; then
    echo "Looks like test/fuzz/fuzz-unit-file/directives.service hasn't been updated"
    ret=1
fi

exit $ret
