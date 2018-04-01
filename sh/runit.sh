# Copyright (c) 2016 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
#    except according to the terms contained in the LICENSE file.
# Released under the 2-clause BSD license.

runit_start()
{
	local service_path service_link
	service_path="${runit_service:-/etc/sv/${RC_SVCNAME}}"
	if [ ! -d "${service_path}" ]; then
		eerror "Runit service ${service_path} not found"
		return 1
	fi
	service_link="${RC_SVCDIR}/sv/${service_path##*/}"
	ebegin "Starting ${name:-$RC_SVCNAME}"
	ln -snf "${service_path}" "${service_link}"
	sv start "${service_link}" > /dev/null 2>&1
	eend $? "Failed to start ${name:-$RC_SVCNAME}"
}

runit_stop()
{
	local service_path service_link
	service_path="${runit_service:-/etc/sv/${RC_SVCNAME}}"
	if [ ! -d "${service_path}" ]; then
		eerror "Runit service ${service_path} not found"
		return 1
	fi
	service_link="${RC_SVCDIR}/sv/${service_path##*/}"
	ebegin "Stopping ${name:-$RC_SVCNAME}"
	sv stop "${service_link}" > /dev/null 2>&1 &&
	rm "${service_link}"
	eend $? "Failed to stop ${name:-$RC_SVCNAME}"
}

runit_status()
{
	local service_path service_link
	service_path="${runit_service:-/etc/sv/${RC_SVCNAME}}"
	if [ ! -d "${service_path}" ]; then
		eerror "Runit service ${service_path} not found"
		return 1
	fi
	service_link="${RC_SVCDIR}/sv/${service_path##*/}"
	sv status "${service_link}"
}
