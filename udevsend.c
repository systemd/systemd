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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "udev.h"
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"

unsigned char logname[42];

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
	strfieldcpy(msg->magic, UDEV_MAGIC);
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
	int sock;
	struct sockaddr_un saddr;

	init_logging("udevsend");

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

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1) {
		dbg("error getting socket");
		goto exit;
	}

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strcpy(saddr.sun_path, UDEVD_SOCK);

	/* try to connect, if it fails start daemon */
	retval = connect(sock, (struct sockaddr *) &saddr, sizeof(saddr));
	if (retval != -1) {
		goto send;
	} else {
		dbg("connect failed, try starting daemon...");
		retval = start_daemon();
		if (retval == 0) {
			dbg("daemon started");
		} else {
			dbg("error starting daemon");
			goto exit;
		}
	}

	/* try to connect while daemon to starts */
	tspec.tv_sec = 0;
	tspec.tv_nsec = 100000000;  /* 100 millisec */
	loop = UDEVSEND_CONNECT_RETRY;
	while (loop--) {
		retval = connect(sock, (struct sockaddr *) &saddr, sizeof(saddr));
		if (retval != -1)
			goto send;
		else
			dbg("retry to connect %d",
			    UDEVSEND_CONNECT_RETRY - loop);
		nanosleep(&tspec, NULL);
	}
	dbg("error connecting to daemon, start daemon failed");
	goto exit;

send:
	size = build_hotplugmsg(&message, action, devpath, subsystem, seq);
	retval = send(sock, &message, size, 0);
	if (retval == -1) {
		dbg("error sending message");
		close (sock);
		goto exit;
	}
	close (sock);
	return 0;

exit:
	return 1;
}
