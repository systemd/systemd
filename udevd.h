/*
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
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

#include "list.h"

#define UDEVD_PRIORITY			-4
#define UDEV_PRIORITY			-2

#define EVENT_QUEUE_DIR			".udev/queue"
#define EVENT_FAILED_DIR		".udev/failed"
#define EVENT_SEQNUM			".udev/uevent_seqnum"

/* maximum limit of forked childs */
#define UDEVD_MAX_CHILDS		256
/* start to throttle forking if maximum number of running childs in our session is reached */
#define UDEVD_MAX_CHILDS_RUNNING	16

/* linux/include/linux/kobject.h */
#define UEVENT_BUFFER_SIZE		2048
#define UEVENT_NUM_ENVP			32

#define UDEVD_CTRL_SOCK_PATH		"/org/kernel/udev/udevd"
#define UDEVD_CTRL_MAGIC		"udevd_" UDEV_VERSION

enum udevd_ctrl_msg_type {
	UDEVD_CTRL_UNKNOWN,
	UDEVD_CTRL_STOP_EXEC_QUEUE,
	UDEVD_CTRL_START_EXEC_QUEUE,
	UDEVD_CTRL_SET_LOG_LEVEL,
	UDEVD_CTRL_SET_MAX_CHILDS,
	UDEVD_CTRL_SET_MAX_CHILDS_RUNNING,
	UDEVD_CTRL_RELOAD_RULES,
};

struct udevd_ctrl_msg {
	char magic[32];
	enum udevd_ctrl_msg_type type;
	char buf[256];
};

struct udevd_uevent_msg {
	struct list_head node;
	pid_t pid;
	int exitstatus;
	time_t queue_time;
	char *action;
	char *devpath;
	char *subsystem;
	char *driver;
	dev_t devt;
	unsigned long long seqnum;
	char *physdevpath;
	unsigned int timeout;
	char *envp[UEVENT_NUM_ENVP+1];
	char envbuf[];
};
