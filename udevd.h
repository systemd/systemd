/*
 * udevd.h
 *
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
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
#define UDEVD_SOCK_PATH			"/org/kernel/udev/udevd"
#define UDEVSEND_WAIT_MAX_SECONDS	3
#define UDEVSEND_WAIT_LOOP_PER_SECOND	10

#define UDEVD_PRIORITY			-4
#define UDEV_PRIORITY			-2

/* maximum limit of runnig childs */
#define UDEVD_MAX_CHILDS		64
/* start to throttle forking if maximum number of running childs in our session is reached */
#define UDEVD_MAX_CHILDS_RUNNING	16

/* environment buffer, should match the kernel's size in lib/kobject_uevent.h */
#define UEVENT_BUFFER_SIZE		1024
#define UEVENT_NUM_ENVP			32

enum udevd_msg_type {
	UDEVD_UNKNOWN,
	UDEVD_UEVENT_UDEVSEND,
	UDEVD_UEVENT_INITSEND,
	UDEVD_UEVENT_NETLINK,
	UDEVD_STOP_EXEC_QUEUE,
	UDEVD_START_EXEC_QUEUE,
	UDEVD_SET_LOG_LEVEL,
	UDEVD_SET_MAX_CHILDS,
	UDEVD_RELOAD_RULES,
};


struct udevd_msg {
	char magic[32];
	enum udevd_msg_type type;
	char envbuf[UEVENT_BUFFER_SIZE+512];
};

struct uevent_msg {
	enum udevd_msg_type type;
	struct list_head node;
	pid_t pid;
	int exitstatus;
	time_t queue_time;
	char *action;
	char *devpath;
	char *subsystem;
	dev_t devt;
	unsigned long long seqnum;
	char *physdevpath;
	unsigned int timeout;
	char *envp[UEVENT_NUM_ENVP+1];
	char envbuf[];
};
