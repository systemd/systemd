/*
 * udevcontrol.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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
void log_message (int level, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif


int main(int argc, char *argv[], char *envp[])
{
	static struct udevd_msg usend_msg;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	int retval = 1;

	logging_init("udevcontrol");
	dbg("version %s", UDEV_VERSION);

	if (argc != 2) {
		info("usage: udevcontrol <cmd>\n");
		goto exit;
	}

	memset(&usend_msg, 0x00, sizeof(struct udevd_msg));
	strcpy(usend_msg.magic, UDEV_MAGIC);

	if (strstr(argv[1], "stop_exec_queue"))
		usend_msg.type = UDEVD_STOP_EXEC_QUEUE;
	else if (strstr(argv[1], "start_exec_queue"))
		usend_msg.type = UDEVD_START_EXEC_QUEUE;
	else {
		info("unknown command\n");
		goto exit;
	}

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		info("error getting socket");
		goto exit;
	}

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;


	retval = sendto(sock, &usend_msg, sizeof(usend_msg), 0, (struct sockaddr *)&saddr, addrlen);
	if (retval == -1) {
		info("error sending message (%s)", strerror(errno));
		retval = 1;
	} else {
		dbg("sent message '%x' (%u bytes sent)\n", usend_msg.type, retval);
		retval = 0;
	}

	close(sock);

exit:
	logging_close();

	return retval;
}
