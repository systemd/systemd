/*
 * udevd.h
 *
 * Userspace devfs
 *
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
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

#define FIRST_EVENT_TIMEOUT_SEC		1
#define EVENT_TIMEOUT_SEC		5
#define UDEVSEND_RETRY_COUNT		50 /* x 10 millisec */

#define IPC_KEY_ID			1
#define HOTPLUGMSGTYPE			44


struct hotplug_msg {
	long mtype;
	struct list_head list;
	pid_t pid;
	int seqnum;
	time_t queue_time;
	char action[8];
	char devpath[128];
	char subsystem[16];
};
