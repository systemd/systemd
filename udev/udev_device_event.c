/*
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "udev.h"
#include "udev_rules.h"


static void kernel_log(struct ifreq ifr)
{
	int klog;
	FILE *f;

	klog = open("/dev/kmsg", O_WRONLY);
	if (klog < 0)
		return;

	f = fdopen(klog, "w");
	if (f == NULL) {
		close(klog);
		return;
	}

	fprintf(f, "<6>udev: renamed network interface %s to %s\n",
		ifr.ifr_name, ifr.ifr_newname);
	fclose(f);
}

static int rename_netif(struct udevice *udevice)
{
	int sk;
	struct ifreq ifr;
	int retval;

	info(udevice->udev, "changing net interface name from '%s' to '%s'\n", udevice->dev->kernel, udevice->name);
	if (udevice->test_run)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err(udevice->udev, "error opening socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, udevice->dev->kernel, IFNAMSIZ);
	strlcpy(ifr.ifr_newname, udevice->name, IFNAMSIZ);
	retval = ioctl(sk, SIOCSIFNAME, &ifr);
	if (retval == 0)
		kernel_log(ifr);
	else {
		int loop;

		/* see if the destination interface name already exists */
		if (errno != EEXIST) {
			err(udevice->udev, "error changing netif name %s to %s: %s\n", ifr.ifr_name, ifr.ifr_newname, strerror(errno));
			goto exit;
		}

		/* free our own name, another process may wait for us */
		strlcpy(ifr.ifr_newname, udevice->dev->kernel, IFNAMSIZ);
		strlcat(ifr.ifr_newname, "_rename", IFNAMSIZ);
		retval = ioctl(sk, SIOCSIFNAME, &ifr);
		if (retval != 0) {
			err(udevice->udev, "error changing netif name %s to %s: %s\n", ifr.ifr_name, ifr.ifr_newname, strerror(errno));
			goto exit;
		}

		/* wait 30 seconds for our target to become available */
		strlcpy(ifr.ifr_name, ifr.ifr_newname, IFNAMSIZ);
		strlcpy(ifr.ifr_newname, udevice->name, IFNAMSIZ);
		loop = 30 * 20;
		while (loop--) {
			retval = ioctl(sk, SIOCSIFNAME, &ifr);
			if (retval == 0) {
				kernel_log(ifr);
				break;
			}

			if (errno != EEXIST) {
				err(udevice->udev, "error changing net interface name %s to %s: %s\n",
				    ifr.ifr_name, ifr.ifr_newname, strerror(errno));
				break;
			}
			dbg(udevice->udev, "wait for netif '%s' to become free, loop=%i\n", udevice->name, (30 * 20) - loop);
			usleep(1000 * 1000 / 20);
		}
	}

exit:
	close(sk);
	return retval;
}

int udev_device_event(struct udev_rules *rules, struct udevice *udevice)
{
	int retval = 0;

	if (udevice->devpath_old != NULL)
		if (udev_db_rename(udevice->udev, udevice->devpath_old, udevice->dev->devpath) == 0)
			info(udevice->udev, "moved database from '%s' to '%s'\n", udevice->devpath_old, udevice->dev->devpath);

	/* add device node */
	if (major(udevice->devt) != 0 &&
	    (strcmp(udevice->action, "add") == 0 || strcmp(udevice->action, "change") == 0)) {
		struct udevice *udevice_old;

		dbg(udevice->udev, "device node add '%s'\n", udevice->dev->devpath);

		udev_rules_get_name(rules, udevice);
		if (udevice->ignore_device) {
			info(udevice->udev, "device event will be ignored\n");
			goto exit;
		}
		if (udevice->name[0] == '\0') {
			info(udevice->udev, "device node creation supressed\n");
			goto exit;
		}

		/* read current database entry; cleanup, if it is known device */
		udevice_old = udev_device_init(udevice->udev);
		if (udevice_old != NULL) {
			udevice_old->test_run = udevice->test_run;
			if (udev_db_get_device(udevice_old, udevice->dev->devpath) == 0) {
				info(udevice->udev, "device '%s' already in database, cleanup\n", udevice->dev->devpath);
				udev_db_delete_device(udevice_old);
			} else {
				udev_device_cleanup(udevice_old);
				udevice_old = NULL;
			}
		}

		/* create node */
		retval = udev_node_add(udevice);
		if (retval != 0)
			goto exit;

		/* store in database */
		udev_db_add_device(udevice);

		/* create, replace, delete symlinks according to priority */
		udev_node_update_symlinks(udevice, udevice_old);

		if (udevice_old != NULL)
			udev_device_cleanup(udevice_old);
		goto exit;
	}

	/* add netif */
	if (strcmp(udevice->dev->subsystem, "net") == 0 && strcmp(udevice->action, "add") == 0) {
		dbg(udevice->udev, "netif add '%s'\n", udevice->dev->devpath);
		udev_rules_get_name(rules, udevice);
		if (udevice->ignore_device) {
			info(udevice->udev, "device event will be ignored\n");
			goto exit;
		}
		if (udevice->name[0] == '\0') {
			info(udevice->udev, "device renaming supressed\n");
			goto exit;
		}

		/* look if we want to change the name of the netif */
		if (strcmp(udevice->name, udevice->dev->kernel) != 0) {
			char devpath[PATH_MAX];
			char *pos;

			retval = rename_netif(udevice);
			if (retval != 0)
				goto exit;
			info(udevice->udev, "renamed netif to '%s'\n", udevice->name);

			/* export old name */
			setenv("INTERFACE_OLD", udevice->dev->kernel, 1);

			/* now change the devpath, because the kernel device name has changed */
			strlcpy(devpath, udevice->dev->devpath, sizeof(devpath));
			pos = strrchr(devpath, '/');
			if (pos != NULL) {
				pos[1] = '\0';
				strlcat(devpath, udevice->name, sizeof(devpath));
				sysfs_device_set_values(udevice->udev, udevice->dev, devpath, NULL, NULL);
				setenv("DEVPATH", udevice->dev->devpath, 1);
				setenv("INTERFACE", udevice->name, 1);
				info(udevice->udev, "changed devpath to '%s'\n", udevice->dev->devpath);
			}
		}
		goto exit;
	}

	/* remove device node */
	if (major(udevice->devt) != 0 && strcmp(udevice->action, "remove") == 0) {
		struct name_entry *name_loop;

		/* import database entry, and delete it */
		if (udev_db_get_device(udevice, udevice->dev->devpath) == 0) {
			udev_db_delete_device(udevice);
			/* restore stored persistent data */
			list_for_each_entry(name_loop, &udevice->env_list, node)
				putenv(name_loop->name);
		} else {
			dbg(udevice->udev, "'%s' not found in database, using kernel name '%s'\n",
			    udevice->dev->devpath, udevice->dev->kernel);
			strlcpy(udevice->name, udevice->dev->kernel, sizeof(udevice->name));
		}

		udev_rules_get_run(rules, udevice);
		if (udevice->ignore_device) {
			info(udevice->udev, "device event will be ignored\n");
			goto exit;
		}

		if (udevice->ignore_remove) {
			info(udevice->udev, "ignore_remove for '%s'\n", udevice->name);
			goto exit;
		}
		/* remove the node */
		retval = udev_node_remove(udevice);

		/* delete or restore symlinks according to priority */
		udev_node_update_symlinks(udevice, NULL);
		goto exit;
	}

	/* default devices */
	udev_rules_get_run(rules, udevice);
	if (udevice->ignore_device)
		info(udevice->udev, "device event will be ignored\n");

exit:
	return retval;
}
