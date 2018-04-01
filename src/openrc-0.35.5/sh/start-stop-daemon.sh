# start / stop / status functions for start-stop-daemon

# Copyright (c) 2007-2015 The OpenRC Authors.
# See the Authors file at the top-level directory of this distribution and
# https://github.com/OpenRC/openrc/blob/master/AUTHORS
#
# This file is part of OpenRC. It is subject to the license terms in
# the LICENSE file found in the top-level directory of this
# distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
# This file may not be copied, modified, propagated, or distributed
#    except according to the terms contained in the LICENSE file.

ssd_start()
{
	if [ -z "$command" ]; then
		ewarn "The command variable is undefined."
		ewarn "There is nothing for ${name:-$RC_SVCNAME} to start."
		ewarn "If this is what you intend, please write a start function."
		ewarn "This will become a failure in a future release."
		return 0
	fi

	local _background=
	ebegin "Starting ${name:-$RC_SVCNAME}"
	if yesno "${command_background}"; then
		if [ -z "${pidfile}" ]; then
			eend 1 "command_background option used but no pidfile specified"
			return 1
		fi
		if [ -n "${command_args_background}" ]; then
			eend 1 "command_background used with command_args_background"
			return 1
		fi
		_background="--background --make-pidfile"
	fi
	if yesno "$start_inactive"; then
		local _inactive=false
		service_inactive && _inactive=true
		mark_service_inactive
	fi
	#the eval call is necessary for cases like:
	# command_args="this \"is a\" test"
	# to work properly.
	eval start-stop-daemon --start \
		--exec $command \
		${chroot:+--chroot} $chroot \
		${directory:+--chdir} $directory \
		${output_log+--stdout} $output_log \
		${error_log+--stderr} $error_log \
		${procname:+--name} $procname \
		${pidfile:+--pidfile} $pidfile \
		${command_user+--user} $command_user \
		${umask+--umask} $umask \
		$_background $start_stop_daemon_args \
		-- $command_args $command_args_background
	if eend $? "Failed to start ${name:-$RC_SVCNAME}"; then
		service_set_value "command" "${command}"
		[ -n "${chroot}" ] && service_set_value "chroot" "${chroot}"
		[ -n "${pidfile}" ] && service_set_value "pidfile" "${pidfile}"
		[ -n "${procname}" ] && service_set_value "procname" "${procname}"
		return 0
	fi
	if yesno "$start_inactive"; then
		if ! $_inactive; then
			mark_service_stopped
		fi
	fi
	return 1
}

ssd_stop()
{
	local _progress=
	local startcommand="$(service_get_value "command")"
	local startchroot="$(service_get_value "chroot")"
	local startpidfile="$(service_get_value "pidfile")"
	local startprocname="$(service_get_value "procname")"
	command="${startcommand:-$command}"
	chroot="${startchroot:-$chroot}"
	pidfile="${startpidfile:-$pidfile}"
	procname="${startprocname:-$procname}"
	[ -n "$command" -o -n "$procname" -o -n "$pidfile" ] || return 0
	yesno "${command_progress}" && _progress=--progress
	ebegin "Stopping ${name:-$RC_SVCNAME}"
	start-stop-daemon --stop \
		${retry:+--retry} $retry \
		${command:+--exec} $command \
		${procname:+--name} $procname \
		${pidfile:+--pidfile} $chroot$pidfile \
		${stopsig:+--signal} $stopsig \
		${_progress}

	eend $? "Failed to stop ${name:-$RC_SVCNAME}"
}

ssd_status()
{
	_status
}
