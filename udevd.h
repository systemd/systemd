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
#define UDEVD_SOCK_PATH			"udevd"
#define SEND_WAIT_MAX_SECONDS		3
#define SEND_WAIT_LOOP_PER_SECOND	10

/* environment buffer, should match the kernel's size in lib/kobject_uevent.h */
#define HOTPLUG_BUFFER_SIZE		1024
#define HOTPLUG_NUM_ENVP		32

struct udevsend_msg {
	char magic[20];
	char envbuf[HOTPLUG_BUFFER_SIZE];
};

struct hotplug_msg {
	struct list_head list;
	pid_t pid;
	long queue_time;
	char *action;
	char *devpath;
	char *subsystem;
	unsigned long long seqnum;
	char *envp[HOTPLUG_NUM_ENVP];
	char envbuf[];
};
