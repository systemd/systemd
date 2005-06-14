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
#include "udev_version.h"
#include "udevd.h"
#include "logging.h"

/* global variables */
static int sock = -1;

#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

static int start_daemon(void)
{
	pid_t pid;
	pid_t child_pid;
	char *const argv[] = { "udevd", NULL };
	char *const envp[] = { NULL };

	pid = fork();
	switch (pid) {
	case 0:
		/* helper child */
		child_pid = fork();
		switch (child_pid) {
		case 0:
			/* daemon with empty environment */
			close(sock);
			execve(UDEVD_BIN, argv, envp);
			err("exec of daemon failed");
			_exit(1);
		case -1:
			err("fork of daemon failed");
			return -1;
		default:
			exit(0);
		}
		break;
	case -1:
		err("fork of helper failed");
		return -1;
	default:
		waitpid(pid, NULL, 0);
	}
	return 0;
}

static void run_udev(const char *subsystem)
{
	char *const argv[] = { "udev", (char *)subsystem, NULL };
	pid_t pid;

	pid = fork();
	switch (pid) {
	case 0:
		/* child */
		execv(UDEV_BIN, argv);
		err("exec of udev child failed");
		_exit(1);
		break;
	case -1:
		err("fork of udev child failed");
		break;
	default:
		waitpid(pid, NULL, 0);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	static struct udevd_msg usend_msg;
	int usend_msg_len;
	int i;
	int loop;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	int bufpos = 0;
	int retval = 1;
	int started_daemon = 0;
	const char *subsystem = NULL;

	logging_init("udevsend");
#ifdef USE_LOG
	udev_init_config();
#endif
	dbg("version %s", UDEV_VERSION);

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		err("error getting socket");
		goto fallback;
	}

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	memset(&usend_msg, 0x00, sizeof(struct udevd_msg));
	strcpy(usend_msg.magic, UDEV_MAGIC);
	usend_msg.type = UDEVD_UDEVSEND;

	/* copy all keys to send buffer */
	for (i = 0; envp[i]; i++) {
		const char *key;
		int keylen;

		key = envp[i];
		keylen = strlen(key);

		/* prevent loops in the scripts we execute */
		if (strncmp(key, "UDEVD_EVENT=", 12) == 0) {
			dbg("seems that the event source is not the kernel, just exit");
			goto exit;
		}

		if (bufpos + keylen >= UEVENT_BUFFER_SIZE-1) {
			err("environment buffer too small, probably not called by the kernel");
			continue;
		}

		/* remember the SUBSYSTEM */
		if (strncmp(key, "SUBSYSTEM=", 10) == 0)
			subsystem = &key[10];

		dbg("add '%s' to env[%i] buffer", key, i);
		strcpy(&usend_msg.envbuf[bufpos], key);
		bufpos += keylen + 1;
	}
	/* older kernels passed the SUBSYSTEM only as the first argument */
	if (!subsystem && argc == 2) {
		bufpos += sprintf(&usend_msg.envbuf[bufpos], "SUBSYSTEM=%s", argv[1]) + 1;
		dbg("add 'SUBSYSTEM=%s' to env[%i] buffer from argv", argv[1], i);
	}

	usend_msg_len = offsetof(struct udevd_msg, envbuf) + bufpos;
	dbg("usend_msg_len=%i", usend_msg_len);

	/* If we can't send, try to start daemon and resend message */
	loop = UDEVSEND_WAIT_MAX_SECONDS * UDEVSEND_WAIT_LOOP_PER_SECOND;
	while (--loop) {
		retval = sendto(sock, &usend_msg, usend_msg_len, 0, (struct sockaddr *)&saddr, addrlen);
		if (retval != -1) {
			retval = 0;
			goto exit;
		}

		if (errno != ECONNREFUSED) {
			err("error sending message (%s)", strerror(errno));
			goto fallback;
		}

		if (!started_daemon) {
			info("try to start udevd daemon");
			retval = start_daemon();
			if (retval) {
				dbg("error starting daemon");
				goto fallback;
			}
			dbg("udevd daemon started");
			started_daemon = 1;
		} else {
			dbg("retry to connect %d", UDEVSEND_WAIT_MAX_SECONDS * UDEVSEND_WAIT_LOOP_PER_SECOND - loop);
			usleep(1000 * 1000 / UDEVSEND_WAIT_LOOP_PER_SECOND);
		}
	}

fallback:
	err("unable to connect to event daemon, try to call udev directly");
	run_udev(subsystem);

exit:
	if (sock != -1)
		close(sock);

	logging_close();

	return retval;
}
