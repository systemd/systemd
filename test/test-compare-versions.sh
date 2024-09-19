#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

ANALYZE="${1:-systemd-analyze}"

"$ANALYZE" compare-versions 1 lt 2
"$ANALYZE" compare-versions 1 '<' 2
"$ANALYZE" compare-versions 1 le 2
"$ANALYZE" compare-versions 1 '<=' 2
"$ANALYZE" compare-versions 1 ne 2
"$ANALYZE" compare-versions 1 '!=' 2
( ! "$ANALYZE" compare-versions 1 ge 2 )
( ! "$ANALYZE" compare-versions 1 '>=' 2 )
( ! "$ANALYZE" compare-versions 1 eq 2 )
( ! "$ANALYZE" compare-versions 1 '==' 2 )
( ! "$ANALYZE" compare-versions 1 gt 2 )
( ! "$ANALYZE" compare-versions 1 '>' 2 )

test "$("$ANALYZE" compare-versions 1 2)" = '1 < 2'
test "$("$ANALYZE" compare-versions 2 2)" = '2 == 2'
test "$("$ANALYZE" compare-versions 2 1)" = '2 > 1'
test "$("$ANALYZE" compare-versions '' '')" = "'' == ''"

set +e

"$ANALYZE" compare-versions 1 2; ret1=$?
"$ANALYZE" compare-versions 2 2; ret2=$?
"$ANALYZE" compare-versions 2 1; ret3=$?

set -e

test "$ret1" == 12
test "$ret2" == 0
test "$ret3" == 11
