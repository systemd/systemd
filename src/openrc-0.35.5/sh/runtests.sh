#!/bin/sh
# Copyright (c) 2008-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
#    except according to the terms contained in the LICENSE file.

: ${top_srcdir:=..}
. $top_srcdir/test/setup_env.sh

ret=0

tret=0
ebegin "Testing yesno()"
for f in yes YES Yes true TRUE True 1 ; do
	if ! yesno $f; then
		: $(( tret += 1 ))
		echo "!$f!"
	fi
done
for f in no NO No false FALSE False 0 ; do
	if yesno $f; then
		: $(( tret += 1 ))
		echo "!$f!"
	fi
done
eend $tret
: $(( ret += $tret ))

exit $ret
