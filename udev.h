/*
 * udev.h
 *
 * Userspace devfs
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef UDEV_H
#define UDEV_H


#ifdef DEBUG
#include <syslog.h>
#define dbg(format, arg...)								\
	do {										\
		log_message (LOG_DEBUG , "%s: " format , __FUNCTION__ , ## arg);	\
	} while (0)
#else
	#define dbg(format, arg...) do { } while (0)
#endif


/* Lots of constants that should be in a config file sometime */

/* Location of sysfs mount */
#define SYSFS_ROOT	"/sys"

/* Where udev should create its device nodes, trailing / needed */
#define UDEV_ROOT	"/udev/"

/* device file in sysfs that contains major/minor number, leading / needed */
#define DEV_FILE	"/dev"

/* Binaries that udev calls to do stuff */
#define MKNOD		"/bin/mknod"

extern int log_message (int level, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

#define NAME_SIZE	100
#define OWNER_SIZE	30
#define GROUP_SIZE	30

struct device_attr {
	char name[NAME_SIZE];
	char owner[OWNER_SIZE];
	char group[GROUP_SIZE];
	int mode;
};

extern int udev_add_device(char *device, char *subsystem);
extern int udev_remove_device(char *device, char *subsystem);

#endif

