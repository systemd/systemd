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

extern dev_t get_devt(struct sysfs_class_device *class_dev);
extern int subsystem_expect_no_dev(const char *subsystem);

/* /sys/class /sys/block devices */
extern struct sysfs_class_device *wait_class_device_open(const char *path);
extern int wait_for_class_device(struct sysfs_class_device *class_dev, const char **error);

/* /sys/devices devices */
extern struct sysfs_device *wait_devices_device_open(const char *path);
extern int wait_for_devices_device(struct sysfs_device *devices_dev, const char **error);

#endif /* _UDEV_SYSFS_H_ */
