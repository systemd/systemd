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
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/stddef.h>

#include "udev.h"
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"

unsigned char logname[42];

int log_ok(void)
{
	return 1;
}

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
	struct hotplug_msg msg;
	char *action;
	char *devpath;
	char *subsystem;
	char *seqnum;
	int seq;
	int retval = 1;
	int size;
	int loop;
	struct timespec tspec;
	int sock;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	int started_daemon = 0;
	struct iovec iov;
	struct msghdr smsg;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	struct cmsghdr *cmsg;
	struct ucred *cred;
	


#ifdef DEBUG
	init_logging("udevsend");
#endif

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
	if (seqnum == NULL)
		seq = -1;
	else
		seq = atoi(seqnum);

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		dbg("error getting socket");
		goto exit;
	}

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	size = build_hotplugmsg(&msg, action, devpath, subsystem, seq);

	/* prepare message with credentials to authenticate ourself */
	iov.iov_base = &msg;
	iov.iov_len = size;

	smsg.msg_name = &saddr;
	smsg.msg_namelen = addrlen;
	smsg.msg_iov = &iov;
	smsg.msg_iovlen = 1;
	smsg.msg_control = cred_msg;
	smsg.msg_controllen = CMSG_LEN(sizeof(struct ucred));;
	smsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&smsg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	cmsg->cmsg_len = sizeof(cred_msg);
	cred = (struct ucred *) CMSG_DATA(cmsg);
	cred->uid = getuid();
	cred->gid = getgid();
	cred->pid = getpid();
	cred->pid = getpid();

	/* If we can't send, try to start daemon and resend message */
	loop = UDEVSEND_CONNECT_RETRY;
	while (loop--) {
		retval = sendmsg(sock, &smsg, 0);
		if (retval != -1) {
			retval = 0;
			goto close_and_exit;
		}
		
		if (errno != ECONNREFUSED) {
			dbg("error sending message");
			goto close_and_exit;
		}
		
		if (!started_daemon) {
			dbg("connect failed, try starting daemon...");
			retval = start_daemon();
			if (retval) {
				dbg("error starting daemon");
				goto exit;
			}
			
			dbg("daemon started");
			started_daemon = 1;
		} else {
			dbg("retry to connect %d", UDEVSEND_CONNECT_RETRY - loop);
			tspec.tv_sec = 0;
			tspec.tv_nsec = 100000000;  /* 100 millisec */
			nanosleep(&tspec, NULL);
		}
	}
	
close_and_exit:
	close(sock);
exit:
	return retval;
}
