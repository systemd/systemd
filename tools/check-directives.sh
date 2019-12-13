#!/bin/bash
set -e

which perl &>/dev/null || exit 77

function generate_directives() {
    perl -aF'/[\s,]+/' -ne '
        if (my ($s, $d) = ($F[0] =~ /^([^\s\.]+)\.([^\s\.]+)$/)) { $d{$s}{"$d="} = 1; }
        END { while (my ($key, $value) = each %d) {
            printf "[%s]\n%s\n", $key, join("\n", keys(%$value))
        }}' "$1"
}

ret=0
if ! diff \
     <(generate_directives "$1"/src/network/networkd-network-gperf.gperf | sort) \
     <(cat "$1"/test/fuzz/fuzz-network-parser/directives.network | sort); then
    echo "Looks like test/fuzz/fuzz-network-parser/directives.network hasn't been updated"
    ret=1
fi

if ! diff \
     <(generate_directives "$1"/src/network/netdev/netdev-gperf.gperf | sort) \
     <(cat "$1"/test/fuzz/fuzz-netdev-parser/directives.netdev | sort); then
    echo "Looks like test/fuzz/fuzz-netdev-parser/directives.netdev hasn't been updated"
    ret=1
fi

if ! diff \
     <(generate_directives "$1"/src/udev/net/link-config-gperf.gperf | sort) \
     <(cat "$1"/test/fuzz/fuzz-link-parser/directives.link | sort) ; then
    echo "Looks like test/fuzz/fuzz-link-parser/directives.link hasn't been updated"
    ret=1
fi

exit $ret
