# Start / stop / status functions for s6 support

# Copyright (c) 2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
#    except according to the terms contained in the LICENSE file.

[ -z "${s6_service_path}" ] && s6_service_path="/var/svc.d/${RC_SVCNAME}"

_s6_force_kill() {
	local pid
	s6_service_link="${RC_SVCDIR}/s6-scan/${s6_service_path##*/}"
	pid="${3%)}"
	[ -z "${pid}" ] && return 0
	if kill -0 "${pid}" 2> /dev/null; then
		ewarn "Sending DOWN & KILL for ${RC_SVCNAME}"
		s6-svc -dk "${s6_service_link}"
		sleep 1
		kill -0 "${pid}" 2>/dev/null && return 1
	fi
	return 0
}

s6_start()
{
	if [ ! -d "${s6_service_path}" ]; then
		eerror "${s6_service_path} does not exist."
 	return 1
 fi
	s6_service_link="${RC_SVCDIR}/s6-scan/${s6_service_path##*/}"
	ebegin "Starting ${name:-$RC_SVCNAME}"
	ln -sf "${s6_service_path}" "${s6_service_link}"
	s6-svscanctl -na "${RC_SVCDIR}"/s6-scan
	sleep 1.5
	s6-svc -u "${s6_service_link}"
	if [ -n "$s6_svwait_options_start" ]; then
		s6-svwait ${s6_svwait_options_start} "${s6_service_link}"
	fi
	sleep 1.5
	set -- $(s6-svstat "${s6_service_link}")
	[ "$1" = "up" ]
	eend $? "Failed to start ${name:-$RC_SVCNAME}"
}

s6_stop()
{
	if [ ! -d "${s6_service_path}" ]; then
		eerror "${s6_service_path} does not exist."
 	return 1
 fi
	s6_service_link="${RC_SVCDIR}/s6-scan/${s6_service_path##*/}"
	ebegin "Stopping ${name:-$RC_SVCNAME}"
	s6-svc -d -wD -T ${s6_service_timeout_stop:-60000} "${s6_service_link}"
	set -- $(s6-svstat "${s6_service_link}")
	[ "$1" = "up" ] && 
		yesno "${s6_force_kill:-yes}" &&
			_s6_force_kill "$@"
	set -- $(s6-svstat "${s6_service_link}")
	[ "$1" = "down" ]
	eend $? "Failed to stop ${name:-$RC_SVCNAME}"
}

s6_status()
{
	s6_service_link="${RC_SVCDIR}/s6-scan/${s6_service_path##*/}"
	if [ -L "${s6_service_link}" ]; then
		s6-svstat "${s6_service_link}"
	else
		_status
	fi
}
