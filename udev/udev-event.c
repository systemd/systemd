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

struct udev_event *udev_event_new(struct udev_device *dev)
{
	struct udev_event *event;

	event = malloc(sizeof(struct udev_event));
	if (event == NULL)
		return NULL;
	memset(event, 0x00, sizeof(struct udev_event));

	event->dev = dev;
	event->udev = udev_device_get_udev(dev);
	udev_list_init(&event->run_list);
	event->mode = 0660;
	util_strlcpy(event->owner, "0", sizeof(event->owner));
	util_strlcpy(event->group, "0", sizeof(event->group));

	dbg(event->udev, "allocated event %p\n", event);
	return event;
}

void udev_event_unref(struct udev_event *event)
{
	udev_list_cleanup(event->udev, &event->run_list);
	dbg(event->udev, "free event %p\n", event);
	free(event);
}

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

static int rename_netif(struct udev_event *event)
{
	struct udev_device *dev = event->dev;
	int sk;
	struct ifreq ifr;
	int err;

	info(event->udev, "changing net interface name from '%s' to '%s'\n",
	     udev_device_get_sysname(dev), event->name);
	if (event->test)
		return 0;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		err(event->udev, "error opening socket: %m\n");
		return -1;
	}

	memset(&ifr, 0x00, sizeof(struct ifreq));
	util_strlcpy(ifr.ifr_name, udev_device_get_sysname(dev), IFNAMSIZ);
	util_strlcpy(ifr.ifr_newname, event->name, IFNAMSIZ);
	err = ioctl(sk, SIOCSIFNAME, &ifr);
	if (err == 0)
		kernel_log(ifr);
	else {
		int loop;

		/* see if the destination interface name already exists */
		if (errno != EEXIST) {
			err(event->udev, "error changing netif name %s to %s: %m\n",
			    ifr.ifr_name, ifr.ifr_newname);
			goto exit;
		}

		/* free our own name, another process may wait for us */
		util_strlcpy(ifr.ifr_newname, udev_device_get_sysname(dev), IFNAMSIZ);
		util_strlcat(ifr.ifr_newname, "_rename", IFNAMSIZ);
		err = ioctl(sk, SIOCSIFNAME, &ifr);
		if (err != 0) {
			err(event->udev, "error changing netif name %s to %s: %m\n",
			    ifr.ifr_name, ifr.ifr_newname);
			goto exit;
		}

		/* wait 30 seconds for our target to become available */
		util_strlcpy(ifr.ifr_name, ifr.ifr_newname, IFNAMSIZ);
		util_strlcpy(ifr.ifr_newname, udev_device_get_devnode(dev), IFNAMSIZ);
		loop = 30 * 20;
		while (loop--) {
			err = ioctl(sk, SIOCSIFNAME, &ifr);
			if (err == 0) {
				kernel_log(ifr);
				break;
			}

			if (errno != EEXIST) {
				err(event->udev, "error changing net interface name %s to %s: %m\n",
				    ifr.ifr_name, ifr.ifr_newname);
				break;
			}
			dbg(event->udev, "wait for netif '%s' to become free, loop=%i\n",
			    udev_device_get_devnode(dev), (30 * 20) - loop);
			usleep(1000 * 1000 / 20);
		}
	}
exit:
	close(sk);
	return err;
}

int udev_event_execute_rules(struct udev_event *event, struct udev_rules *rules)
{
	struct udev_device *dev = event->dev;
	int err = 0;

	if (udev_device_get_devpath_old(dev) != NULL) {
		if (udev_device_rename_db(dev, udev_device_get_devpath(dev)) == 0)
			info(event->udev, "moved database from '%s' to '%s'\n",
			     udev_device_get_devpath_old(dev), udev_device_get_devpath(dev));
	}

	/* add device node */
	if (major(udev_device_get_devnum(dev)) != 0 &&
	    (strcmp(udev_device_get_action(dev), "add") == 0 || strcmp(udev_device_get_action(dev), "change") == 0)) {
		char filename[UTIL_PATH_SIZE];
		struct udev_device *dev_old;

		dbg(event->udev, "device node add '%s'\n", udev_device_get_devpath(dev));

		udev_rules_get_name(rules, event);
		if (event->ignore_device) {
			info(event->udev, "device event will be ignored\n");
			goto exit;
		}

		if (event->name[0] == '\0') {
			info(event->udev, "device node creation supressed\n");
			goto exit;
		}

		/* set device node name */
		util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
		util_strlcat(filename, "/", sizeof(filename));
		util_strlcat(filename, event->name, sizeof(filename));
		udev_device_set_devnode(dev, filename);

		/* read current database entry; cleanup, if it is known device */
		dev_old = udev_device_new_from_syspath(event->udev, udev_device_get_syspath(dev));
		if (dev_old != NULL) {
			info(event->udev, "device '%s' already in database, updating\n",
			     udev_device_get_devpath(dev));
			udev_node_update_old_links(dev, dev_old, event->test);
			udev_device_unref(dev_old);
		}

		udev_device_update_db(dev);

		err = udev_node_add(dev, event->mode, event->owner, event->group, event->test);
		if (err != 0)
			goto exit;

		goto exit;
	}

	/* add netif */
	if (strcmp(udev_device_get_subsystem(dev), "net") == 0 && strcmp(udev_device_get_action(dev), "add") == 0) {
		dbg(event->udev, "netif add '%s'\n", udev_device_get_devpath(dev));

		udev_rules_get_name(rules, event);
		if (event->ignore_device) {
			info(event->udev, "device event will be ignored\n");
			goto exit;
		}
		if (event->name[0] == '\0') {
			info(event->udev, "device renaming supressed\n");
			goto exit;
		}

		/* look if we want to change the name of the netif */
		if (strcmp(event->name, udev_device_get_sysname(dev)) != 0) {
			char syspath[UTIL_PATH_SIZE];
			char *pos;

			err = rename_netif(event);
			if (err != 0)
				goto exit;
			info(event->udev, "renamed netif to '%s'\n", event->name);

			/* remember old name */
			udev_device_add_property(dev, "INTERFACE_OLD", udev_device_get_sysname(dev));

			/* now change the devpath, because the kernel device name has changed */
			util_strlcpy(syspath, udev_device_get_syspath(dev), sizeof(syspath));
			pos = strrchr(syspath, '/');
			if (pos != NULL) {
				pos[1] = '\0';
				util_strlcat(syspath, event->name, sizeof(syspath));
				udev_device_set_syspath(event->dev, syspath);
				udev_device_add_property(dev, "INTERFACE", udev_device_get_sysname(dev));
				info(event->udev, "changed devpath to '%s'\n", udev_device_get_devpath(dev));
			}
		}
		goto exit;
	}

	/* remove device node */
	if (major(udev_device_get_devnum(dev)) != 0 && strcmp(udev_device_get_action(dev), "remove") == 0) {
		/* import database entry and delete it */
		udev_device_read_db(dev);
		if (!event->test)
			udev_device_delete_db(dev);

		if (udev_device_get_devnode(dev) == NULL) {
			char devnode[UTIL_PATH_SIZE];

			info(event->udev, "'%s' not found in database, using kernel name '%s'\n",
			     udev_device_get_syspath(dev), udev_device_get_sysname(dev));
			util_strlcpy(devnode, udev_get_dev_path(event->udev), sizeof(devnode));
			util_strlcat(devnode, "/", sizeof(devnode));
			util_strlcat(devnode, udev_device_get_sysname(dev), sizeof(devnode));
			udev_device_set_devnode(dev, devnode);
		}

		udev_rules_get_run(rules, event);
		if (event->ignore_device) {
			info(event->udev, "device event will be ignored\n");
			goto exit;
		}

		if (udev_device_get_ignore_remove(dev)) {
			info(event->udev, "ignore_remove for '%s'\n", udev_device_get_devnode(dev));
			goto exit;
		}

		err = udev_node_remove(dev, event->test);
		goto exit;
	}

	/* default devices */
	udev_rules_get_run(rules, event);
	if (event->ignore_device)
		info(event->udev, "device event will be ignored\n");
exit:
	return err;
}
