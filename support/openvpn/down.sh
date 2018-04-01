#!/bin/sh
# Copyright (c) 2007-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
#    except according to the terms contained in the LICENSE file.

# If we have a service specific script, run this now
[ -x "${RC_SVCNAME}"-down.sh ] && "${RC_SVCNAME}"-down.sh

# Restore resolv.conf to how it was
if command -v resolvconf >/dev/null 2>&1; then
	resolvconf -d "${dev}"
elif [ -e /etc/resolv.conf-"${dev}".sv ]; then
	# Important that we copy instead of move incase resolv.conf is
	# a symlink and not an actual file
	cp -p /etc/resolv.conf-"${dev}".sv /etc/resolv.conf
	rm -f /etc/resolv.conf-"${dev}".sv
fi

# Re-enter the init script to stop any dependant services
if [ -x "${RC_SERVICE}" ]; then
	if "${RC_SERVICE}" --quiet status; then
		IN_BACKGROUND=YES
		export IN_BACKGROUND
		"${RC_SERVICE}" --quiet stop
	fi
fi

exit 0
