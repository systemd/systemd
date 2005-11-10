#/bin/sh

[ -d /events ] || exit 0
set > /events/debug.$SEQNUM.$1.$ACTION.$$
