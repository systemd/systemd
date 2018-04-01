#!/bin/sh
# Copyright (c) 1999-2007 Gentoo Foundation
# Copyright (c) 2007-2009 Roy Marples <roy@marples.name>
# Released under the 2-clause BSD license.

. "$RC_LIBEXECDIR"/sh/functions.sh
[ -r "/etc/rc.conf" ] && . "/etc/rc.conf"
if [ -d "/etc/rc.conf.d" ]; then
	for _f in "/etc"/rc.conf.d/*.conf; do
		[ -e "$_f" ] && . "$_f"
	done
fi

# check for md5sum, and probably /usr too
if command -v md5sum >/dev/null; then
	got_md5sum=true
else
	eerror "md5sum is missing, which suggests /usr is not mounted"
	eerror "If you have separate /usr, it must be mounted by initramfs"
	eerror "If not, you should check coreutils is installed correctly"
	got_md5sum=false
fi

# By default VServer already has /proc mounted, but OpenVZ does not!
# However, some of our users have an old proc image in /proc
# NFC how they managed that, but the end result means we have to test if
# /proc actually works or not. We do this by comparing two reads of
# /proc/self/environ for which we have set the variable VAR to two
# different values. If the comparison comes back equal, we know that
# /proc is not working.
mountproc=true
f=/proc/self/environ
if [ -e $f ]; then
	if $got_md5sum && [ "$(VAR=a md5sum $f)" = "$(VAR=b md5sum $f)" ]; then
		eerror "You have cruft in /proc that should be deleted"
	else
		# If they don't have md5sum, this will fail in pretty ways if
		# /proc isn't really mounted.  Oh well, their system is busted
		# anyway, and they get to keep the pieces.
		einfo "/proc is already mounted"
		mountproc=false
	fi
fi
unset f

if $mountproc; then
	ebegin "Mounting /proc"
	if ! fstabinfo --mount /proc; then
		mount -n -t proc -o noexec,nosuid,nodev proc /proc
	fi
	eend $?
fi

# /run is a new directory for storing volatile runtime data.
# Read more about /run at https://lwn.net/Articles/436012
sys="$(openrc --sys)"

if [ ! -d /run ]; then
	if [ "$sys" = VSERVER ]; then
		if [ -e /run ]; then
		rm -rf /run
		fi
		mkdir /run
	else
		eerror "The /run directory does not exist. Unable to continue."
		return 1
	fi
fi

if [ "$sys" = VSERVER ]; then
	rm -rf /run/*
elif ! mountinfo -q /run; then
	ebegin "Mounting /run"
	rc=0
	if ! fstabinfo --mount /run; then
		mount -t tmpfs -o mode=0755,nodev,size=10% tmpfs /run
		rc=$?
	fi
	if [ $rc != 0 ]; then
		eerror "Unable to mount tmpfs on /run."
		eerror "Can't continue."
		exit 1
	fi
fi

[ -x /sbin/restorecon ] && /sbin/restorecon -rF /run
checkpath -d $RC_SVCDIR
checkpath -d -m 0775 -o root:uucp /run/lock

# Try to mount xenfs as early as possible, otherwise rc_sys() will always
# return RC_SYS_XENU and will think that we are in a domU while it's not.
if grep -Eq "[[:space:]]+xenfs$" /proc/filesystems; then
	ebegin "Mounting xenfs"
	if ! fstabinfo --mount /proc/xen; then
		mount -n -t xenfs xenfs /proc/xen -o nosuid,nodev,noexec
	fi
	eend $?
fi

if [ -e "$RC_LIBEXECDIR"/cache/softlevel ]; then
	cp -p "$RC_LIBEXECDIR"/cache/* "$RC_SVCDIR" 2>/dev/null
fi

echo sysinit >"$RC_SVCDIR"/softlevel
exit 0
