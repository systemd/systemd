/*
 * udevd.h
 *
 * Userspace devfs
 *
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
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

#include "list.h"

#define UDEV_MAGIC			"udevd_" UDEV_VERSION
#define EVENT_TIMEOUT_SEC		10
#define UDEVSEND_CONNECT_RETRY		20 /* x 100 millisec */
#define UDEVD_SOCK_PATH			"udevd"

struct hotplug_msg {
	char magic[20];
	struct list_head list;
	pid_t pid;
	int seqnum;
	long queue_time;
	char action[ACTION_SIZE];
	char devpath[DEVPATH_SIZE];
	char subsystem[SUBSYSTEM_SIZE];
};
