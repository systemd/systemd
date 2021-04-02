#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

SOURCE_ROOT="${1:?Missing argument: project source root}"
BUILD_ROOT="${2:?Missing argument: project build root}"

command -v gawk &>/dev/null || exit 77

function generate_directives() {
    gawk -v sec_limit="${2:-""}" '
    match($0, /^([^ \t\.]+)\.([^ \t\.,]+)/, m) {
        # res[section][directive] = 1
        res[m[1]][m[2]] = 1;
    }
    END {
        for (section in res) {
            if (sec_limit && section != sec_limit)
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
     <(sort "$SOURCE_ROOT"/test/fuzz/fuzz-network-parser/directives.network); then
    echo "Looks like test/fuzz/fuzz-network-parser/directives.network hasn't been updated"
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

for section in Install Mount Scope Service Slice Socket Swap Unit; do
    if ! diff \
         <(generate_directives "$BUILD_ROOT"/src/core/load-fragment-gperf.gperf "$section" | sort) \
         <(sort "$SOURCE_ROOT/test/fuzz/fuzz-unit-file/directives.${section,,}") ; then
        echo "Looks like test/fuzz/fuzz-unit-file/directives.${section,,} hasn't been updated"
        ret=1
    fi
done

exit $ret
