 /etc/dev.d/  How it works, and what it is for
 
 by Greg Kroah-Hartman <greg@kroah.com> March 2004

The /etc/dev.d directory works much like the /etc/hotplug.d/ directory
in that it is a place to put symlinks or programs that get called when
an event happens in the system.  Programs will get called whenever the
device naming program in the system has either named a new device and
created a /dev node for it, or when a /dev node has been removed from
the system due to a device being removed.

The directory tree under /etc/dev.d/ dictate which program is run first,
and when some programs will be run or not.  The device naming program
calls the programs in the following order:
	/etc/dev.d/DEVNAME/*.dev
	/etc/dev.d/SUBSYSTEM/*.dev
	/etc/dev.d/default/*.dev

The .dev extension is needed to allow automatic package managers to
deposit backup files in these directories safely.

The DEVNAME name is the name of the /dev file that has been created, or
for network devices, the name of the newly named network device.  This
value, including the /dev path, will also be exported to userspace in
the DEVNAME environment variable.

The SUBSYSTEM name is the name of the sysfs subsystem that originally
generated the hotplug event that caused the device naming program to
create or remove the /dev node originally.  This value is passed to
userspace as the first argument to the program.

The default directory will always be run, to enable programs to catch
every device add and remove in a single place.

All environment variables that were originally passed by the hotplug
call that caused this device action will also be passed to the program
called in the /etc/dev.d/ directories.  Examples of these variables are
ACTION, DEVPATH, and others.  See the hotplug documentation for full
description of this

An equivalent shell script that would do this same kind of action would
be:
	DIR="/etc/dev.d"
	export DEVNAME="whatever_dev_name_udev_just_gave"
	for I in "${DIR}/$DEVNAME/"*.dev "${DIR}/$1/"*.dev "${DIR}/default/"*.dev ; do
		if [ -f $I ]; then $I $1 ; fi
	done
	exit 1;


