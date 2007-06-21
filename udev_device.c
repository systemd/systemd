/*
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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


struct udevice *udev_device_init(struct udevice *udev)
{
	if (udev == NULL)
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
	unsigned int maj, min;

	/* read it from sysfs  */
	attr = sysfs_attr_get_value(udev->dev->devpath, "dev");
	if (attr != NULL) {
		if (sscanf(attr, "%u:%u", &maj, &min) == 2)
			return makedev(maj, min);
	}
	return makedev(0, 0);
}

static int rename_netif(struct udevice *udev)
{
	int sk;
	struct ifreq ifr;
	int retval;

	info("changing net interface name from '%s' to '%s'", udev->dev->kernel, udev->name);
	if (udev->test_run)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err("error opening socket: %s", strerror(errno));
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, udev->dev->kernel, IFNAMSIZ);
	strlcpy(ifr.ifr_newname, udev->name, IFNAMSIZ);
	retval = ioctl(sk, SIOCSIFNAME, &ifr);
	if (retval != 0) {
		int loop;

		/* see if the destination interface name already exists */
		if (errno != EEXIST) {
			err("error changing netif name %s to %s: %s", ifr.ifr_name, ifr.ifr_newname, strerror(errno));
			goto exit;
		}

		/* free our own name, another process may wait for us */
		strlcpy(ifr.ifr_newname, udev->dev->kernel, IFNAMSIZ);
		strlcat(ifr.ifr_newname, "_rename", IFNAMSIZ);
		retval = ioctl(sk, SIOCSIFNAME, &ifr);
		if (retval != 0) {
			err("error changing netif name %s to %s: %s", ifr.ifr_name, ifr.ifr_newname, strerror(errno));
			goto exit;
		}

		/* wait 30 seconds for our target to become available */
		strlcpy(ifr.ifr_name, ifr.ifr_newname, IFNAMSIZ);
		strlcpy(ifr.ifr_newname, udev->name, IFNAMSIZ);
		loop = 30 * 20;
		while (loop--) {
			retval = ioctl(sk, SIOCSIFNAME, &ifr);
			if (retval == 0)
				break;

			if (errno != EEXIST) {
				err("error changing net interface name %s to %s: %s",
				    ifr.ifr_name, ifr.ifr_newname, strerror(errno));
				break;
			}
			dbg("wait for netif '%s' to become free, loop=%i", udev->name, (30 * 20) - loop);
			usleep(1000 * 1000 / 20);
		}
	}

exit:
	close(sk);
	return retval;
}

int udev_device_event(struct udev_rules *rules, struct udevice *udev)
{
	int retval = 0;

	/* add device node */
	if (major(udev->devt) != 0 &&
	    (strcmp(udev->action, "add") == 0 || strcmp(udev->action, "change") == 0)) {
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

		/* read current database entry; cleanup, if it is known device */
		udev_old = udev_device_init(NULL);
		if (udev_old != NULL) {
			udev_old->test_run = udev->test_run;
			if (udev_db_get_device(udev_old, udev->dev->devpath) == 0) {
				info("device '%s' already in database, cleanup", udev->dev->devpath);
				udev_db_delete_device(udev_old);
			} else {
				udev_device_cleanup(udev_old);
				udev_old = NULL;
			}
		}

		/* create node */
		retval = udev_node_add(udev);
		if (retval != 0)
			goto exit;

		/* store in database */
		udev_db_add_device(udev);

		/* create, replace, delete symlinks according to priority */
		udev_node_update_symlinks(udev, udev_old);

		if (udev_old != NULL)
			udev_device_cleanup(udev_old);
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
		if (udev->name[0] == '\0') {
			info("device renaming supressed");
			goto exit;
		}

		/* look if we want to change the name of the netif */
		if (strcmp(udev->name, udev->dev->kernel) != 0) {
			char devpath[PATH_MAX];
			char *pos;

			retval = rename_netif(udev);
			if (retval != 0)
				goto exit;
			info("renamed netif to '%s'", udev->name);

			/* export old name */
			setenv("INTERFACE_OLD", udev->dev->kernel, 1);

			/* now change the devpath, because the kernel device name has changed */
			strlcpy(devpath, udev->dev->devpath, sizeof(devpath));
			pos = strrchr(devpath, '/');
			if (pos != NULL) {
				pos[1] = '\0';
				strlcat(devpath, udev->name, sizeof(devpath));
				sysfs_device_set_values(udev->dev, devpath, NULL, NULL);
				setenv("DEVPATH", udev->dev->devpath, 1);
				setenv("INTERFACE", udev->name, 1);
				info("changed devpath to '%s'", udev->dev->devpath);
			}
		}
		goto exit;
	}

	/* remove device node */
	if (major(udev->devt) != 0 && strcmp(udev->action, "remove") == 0) {
		struct name_entry *name_loop;

		/* import database entry, and delete it */
		if (udev_db_get_device(udev, udev->dev->devpath) == 0) {
			udev_db_delete_device(udev);
			if (udev->ignore_remove) {
				info("ignore_remove for '%s'", udev->name);
				goto exit;
			}
			/* restore stored persistent data */
			list_for_each_entry(name_loop, &udev->env_list, node)
				putenv(name_loop->name);
		} else {
			dbg("'%s' not found in database, using kernel name '%s'",
			    udev->dev->devpath, udev->dev->kernel);
			strlcpy(udev->name, udev->dev->kernel, sizeof(udev->name));
		}

		udev_rules_get_run(rules, udev);
		if (udev->ignore_device) {
			info("device event will be ignored");
			goto exit;
		}

		/* remove the node */
		retval = udev_node_remove(udev);

		/* delete or restore symlinks according to priority */
		udev_node_update_symlinks(udev, NULL);
		goto exit;
	}

	/* default devices */
	udev_rules_get_run(rules, udev);
	if (udev->ignore_device)
		info("device event will be ignored");

exit:
	return retval;
}
