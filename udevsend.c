/*
 * udevsend.c
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

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <wait.h>

#include "udev.h"
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"

static inline char *get_action(void)
{
	char *action;

	action = getenv("ACTION");
	return action;
}

static inline char *get_devpath(void)
{
	char *devpath;

	devpath = getenv("DEVPATH");
	return devpath;
}

static inline char *get_seqnum(void)
{
	char *seqnum;

	seqnum = getenv("SEQNUM");
	return seqnum;
}

static int build_hotplugmsg(struct hotplug_msg *msg, char *action,
			    char *devpath, char *subsystem, int seqnum)
{
	memset(msg, 0x00, sizeof(*msg));
	msg->mtype = HOTPLUGMSGTYPE;
	msg->seqnum = seqnum;
	strncpy(msg->action, action, 8);
	strncpy(msg->devpath, devpath, 128);
	strncpy(msg->subsystem, subsystem, 16);
	return sizeof(struct hotplug_msg);
}

static int start_daemon(void)
{
	pid_t pid;
	pid_t child_pid;

	pid = fork();
	switch (pid) {
	case 0:
		/* helper child */
		child_pid = fork();
		switch (child_pid) {
		case 0:
			/* daemon */
			setsid();
			chdir("/");
			execl(UDEVD_BIN, "udevd", NULL);
			dbg("exec of daemon failed");
			exit(1);
		case -1:
			dbg("fork of daemon failed");
			return -1;
		default:
			exit(0);
		}
		break;
	case -1:
		dbg("fork of helper failed");
		return -1;
	default:
		wait(NULL);
	}
	return 0;
}


int main(int argc, char* argv[])
{
	int msgid;
	key_t key;
	struct msqid_ds msg_queue;
	struct hotplug_msg message;
	char *action;
	char *devpath;
	char *subsystem;
	char *seqnum;
	int seq;
	int retval = -EINVAL;
	int size;
	int loop;
	struct timespec tspec;

	subsystem = argv[1];
	if (subsystem == NULL) {
		dbg("no subsystem");
		goto exit;
	}

	devpath = get_devpath();
	if (devpath == NULL) {
		dbg("no devpath");
		goto exit;
	}

	action = get_action();
	if (action == NULL) {
		dbg("no action");
		goto exit;
	}

	seqnum = get_seqnum();
	if (seqnum == NULL) {
		dbg("no seqnum");
		goto exit;
	}
	seq = atoi(seqnum);

	/* create ipc message queue or get id of our existing one */
	key = ftok(UDEVD_BIN, IPC_KEY_ID);
	dbg("using ipc queue 0x%0x", key);
	size =  build_hotplugmsg(&message, action, devpath, subsystem, seq);
	msgid = msgget(key, IPC_CREAT);
	if (msgid == -1) {
		dbg("error open ipc queue");
		goto exit;
	}

	/* send ipc message to the daemon */
	retval = msgsnd(msgid, &message, size, 0);
	if (retval == -1) {
		dbg("error sending ipc message");
		goto exit;
	}

	/* get state of ipc queue */
	tspec.tv_sec = 0;
	tspec.tv_nsec = 10000000;  /* 10 millisec */
	loop = UDEVSEND_RETRY_COUNT;
	while (loop--) {
		retval = msgctl(msgid, IPC_STAT, &msg_queue);
		if (retval == -1) {
			dbg("error getting info on ipc queue");
			goto exit;
		}
		if (msg_queue.msg_qnum == 0)
			goto exit;
		nanosleep(&tspec, NULL);
	}

	info("message is still in the ipc queue, starting daemon...");
	retval = start_daemon();

exit:
	return retval;
}
