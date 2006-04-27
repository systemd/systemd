/*
 * udev_device.c - main udev data object
 *
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
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


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "udev.h"
#include "udev_rules.h"


struct udevice *udev_device_init(void)
{
	struct udevice *udev;

	udev = malloc(sizeof(struct udevice));
	if (udev == NULL)
		return NULL;
	memset(udev, 0x00, sizeof(struct udevice));

	INIT_LIST_HEAD(&udev->symlink_list);
	INIT_LIST_HEAD(&udev->run_list);
	INIT_LIST_HEAD(&udev->env_list);

	/* set sysfs device to local storage, can be overridden if needed */
	udev->dev = &udev->dev_local;

	/* default node permissions */
	udev->mode = 0660;
	strcpy(udev->owner, "root");
	strcpy(udev->group, "root");

	return udev;
}

void udev_device_cleanup(struct udevice *udev)
{
	name_list_cleanup(&udev->symlink_list);
	name_list_cleanup(&udev->run_list);
	name_list_cleanup(&udev->env_list);
	free(udev);
}

dev_t udev_device_get_devt(struct udevice *udev)
{
	const char *attr;
	unsigned int major, minor;

	/* read it from sysfs  */
	attr = sysfs_attr_get_value(udev->dev->devpath, "dev");
	if (attr != NULL) {
		if (sscanf(attr, "%u:%u", &major, &minor) == 2)
			return makedev(major, minor);
	}
	return makedev(0, 0);
}

static int rename_net_if(struct udevice *udev)
{
	int sk;
	struct ifreq ifr;
	int retval;

	info("changing net interface name from '%s' to '%s'", udev->dev->kernel_name, udev->name);
	if (udev->test_run)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err("error opening socket: %s", strerror(errno));
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, udev->dev->kernel_name, IFNAMSIZ);
	strlcpy(ifr.ifr_newname, udev->name, IFNAMSIZ);

	retval = ioctl(sk, SIOCSIFNAME, &ifr);
	if (retval != 0)
		err("error changing net interface name: %s", strerror(errno));
	close(sk);

	return retval;
}

int udev_device_event(struct udev_rules *rules, struct udevice *udev)
{
	int retval = 0;

	/* add device node */
	if (major(udev->devt) != 0 && strcmp(udev->action, "add") == 0) {
		struct udevice *udev_old;

		dbg("device node add '%s'", udev->dev->devpath);

		udev_rules_get_name(rules, udev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			goto exit;
		}
		if (udev->name[0] == '\0') {
			info("device node creation supressed");
			goto exit;
		}

		/* read current database entry, we may want to cleanup symlinks */
		udev_old = udev_device_init();
		if (udev_old != NULL) {
			if (udev_db_get_device(udev_old, udev->dev->devpath) == 0) {
				info("device '%s' already known, remove possible symlinks", udev->dev->devpath);
				udev_node_remove_symlinks(udev_old);
			}
			udev_device_cleanup(udev_old);
		}

		/* create node and symlinks, store record in database */
		retval = udev_node_add(udev, udev_old);
		if (retval == 0)
			udev_db_add_device(udev);
		goto exit;
	}

	/* add netif */
	if (strcmp(udev->dev->subsystem, "net") == 0 && strcmp(udev->action, "add") == 0) {
		dbg("netif add '%s'", udev->dev->devpath);
		udev_rules_get_name(rules, udev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			goto exit;
		}

		/* look if we want to change the name of the netif */
		if (strcmp(udev->name, udev->dev->kernel_name) != 0) {
			char *pos;

			retval = rename_net_if(udev);
			if (retval != 0)
				goto exit;
			info("renamed netif to '%s'", udev->name);

			/* export old name */
			setenv("INTERFACE_OLD", udev->dev->kernel_name, 1);

			/* now fake the devpath, because the kernel name changed silently */
			pos = strrchr(udev->dev->devpath, '/');
			if (pos != NULL) {
				pos[1] = '\0';
				strlcat(udev->dev->devpath, udev->name, sizeof(udev->dev->devpath));
				strlcpy(udev->dev->kernel_name, udev->name, sizeof(udev->dev->kernel_name));
				setenv("DEVPATH", udev->dev->devpath, 1);
				setenv("INTERFACE", udev->name, 1);
			}
		}
		goto exit;
	}

	/* remove device node */
	if (major(udev->devt) != 0 && strcmp(udev->action, "remove") == 0) {
		struct name_entry *name_loop;

		/* import and delete database entry */
		if (udev_db_get_device(udev, udev->dev->devpath) == 0) {
			udev_db_delete_device(udev);
			if (udev->ignore_remove) {
				dbg("remove event for '%s' requested to be ignored by rule", udev->name);
				return 0;
			}
			/* restore stored persistent data */
			list_for_each_entry(name_loop, &udev->env_list, node)
				putenv(name_loop->name);
		} else {
			dbg("'%s' not found in database, using kernel name '%s'", udev->dev->devpath, udev->dev->kernel_name);
			strlcpy(udev->name, udev->dev->kernel_name, sizeof(udev->name));
		}

		udev_rules_get_run(rules, udev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			goto exit;
		}

		retval = udev_node_remove(udev);
		goto exit;
	}

	/* default devices */
	udev_rules_get_run(rules, udev);
	if (udev->ignore_device)
		info("device event will be ignored");

exit:
	return retval;
}
