#!/bin/bash

set -e

function generate_directives() {
    perl -aF'/[\s,]+/' -ne '
        if (my ($s, $d) = ($F[0] =~ /^([^\s\.]+)\.([^\s\.]+)$/)) { $d{$s}{"$d="} = 1; }
        END { while (my ($key, $value) = each %d) {
            printf "[%s]\n%s\n", $key, join("\n", keys(%$value))
        }}' "$1"
}

ret=0
if [[ $(generate_directives src/network/networkd-network-gperf.gperf | wc -l) -ne $(wc -l <test/fuzz/fuzz-network-parser/directives.network) ]]; then
	echo "Looks like test/fuzz/fuzz-network-parser/directives.network hasn't been updated"
        ret=1
fi

if [[ $(generate_directives src/network/netdev/netdev-gperf.gperf | wc -l) -ne $(wc -l <test/fuzz/fuzz-netdev-parser/directives.netdev) ]]; then
	echo "Looks like test/fuzz/fuzz-netdev-parser/directives.netdev hasn't been updated"
	ret=1
fi

if [[ $(generate_directives src/udev/net/link-config-gperf.gperf | wc -l) -ne $(wc -l <test/fuzz/fuzz-link-parser/directives.link) ]]; then
	echo "Looks like test/fuzz/fuzz-link-parser/directives.link hasn't been updated"
	ret=1
fi

exit $ret
