/*
 * udev_sysfs.h
 *
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
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

#ifndef _UDEV_SYSFS_H_
#define _UDEV_SYSFS_H_

#include "libsysfs/sysfs/libsysfs.h"

#define WAIT_MAX_SECONDS		5
#define WAIT_LOOP_PER_SECOND		20

extern int subsystem_expect_no_dev(const char *subsystem);
extern int wait_for_bus_device(struct sysfs_device *devices_dev, const char **error);
extern int wait_for_class_device(struct sysfs_class_device *class_dev, const char **error);
extern struct sysfs_class_device *open_class_device_wait(const char *path);
extern struct sysfs_device *open_devices_device_wait(const char *path);

#endif /* _UDEV_SYSFS_H_ */
