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
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <linux/stddef.h>

#include "udev.h"
#include "udev_lib.h"
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message (int level, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

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
		waitpid(pid, NULL, 0);
	}
	return 0;
}

static void run_udev(const char *subsystem)
{
	pid_t pid;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execl(UDEV_BIN, "udev", subsystem, NULL);
		dbg("exec of child failed");
		_exit(1);
		break;
	case -1:
		dbg("fork of child failed");
		break;
	default:
		waitpid(pid, NULL, 0);
	}
}

int main(int argc, char* argv[])
{
	struct hotplug_msg msg;
	char *action;
	char *devpath;
	char *subsystem;
	char *seqnum;
	unsigned long long seq;
	int retval = 1;
	int loop;
	int sock = -1;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	int started_daemon = 0;

	logging_init("udevsend");
	dbg("version %s", UDEV_VERSION);

	subsystem = get_subsystem(argv[1]);
	if (subsystem == NULL) {
		dbg("no subsystem");
		goto exit;
	}
	dbg("subsystem = '%s'", subsystem);

	devpath = get_devpath();
	if (devpath == NULL) {
		dbg("no devpath");
		goto exit;
	}
	dbg("DEVPATH = '%s'", devpath);

	action = get_action();
	if (action == NULL) {
		dbg("no action");
		goto exit;
	}
	dbg("ACTION = '%s'", action);

	seqnum = get_seqnum();
	if (seqnum == NULL)
		seq = 0;
	else
		seq = strtoull(seqnum, NULL, 10);
	dbg("SEQNUM = '%llu'", seq);

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		dbg("error getting socket");
		goto fallback;
	}

	set_cloexec_flag(sock, 1);

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	memset(&msg, 0x00, sizeof(struct hotplug_msg));
	strcpy(msg.magic, UDEV_MAGIC);
	msg.seqnum = seq;
	strfieldcpy(msg.action, action);
	strfieldcpy(msg.devpath, devpath);
	strfieldcpy(msg.subsystem, subsystem);

	/* If we can't send, try to start daemon and resend message */
	loop = SEND_WAIT_MAX_SECONDS * SEND_WAIT_LOOP_PER_SECOND;
	while (--loop) {
		retval = sendto(sock, &msg, sizeof(struct hotplug_msg), 0,
				(struct sockaddr *)&saddr, addrlen);
		if (retval != -1) {
			retval = 0;
			goto exit;
		}

		if (errno != ECONNREFUSED) {
			dbg("error sending message");
			goto fallback;
		}

		if (!started_daemon) {
			dbg("try to start udevd daemon");
			retval = start_daemon();
			if (retval) {
				info("error starting daemon");
				goto fallback;
			}
			info("udevd daemon started");
			started_daemon = 1;
		} else {
			dbg("retry to connect %d", SEND_WAIT_MAX_SECONDS * SEND_WAIT_LOOP_PER_SECOND - loop);
			usleep(1000 * 1000 / SEND_WAIT_LOOP_PER_SECOND);
		}
	}

fallback:
	info("unable to connect to event daemon, try to call udev directly");
	run_udev(subsystem);

exit:
	if (sock != -1)
		close(sock);

	logging_close();

	return retval;
}
