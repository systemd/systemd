/*
 * udevsend.c
 *
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
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

int main(int argc, char *argv[], char *envp[])
{
	static struct udevd_msg usend_msg;
	int usend_msg_len;
	int i;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	int bufpos = 0;
	int retval = 0;
	const char *subsystem = NULL;

	logging_init("udevsend");
#ifdef USE_LOG
	udev_init_config();
#endif
	dbg("version %s", UDEV_VERSION);

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock < 0) {
		err("error getting socket: %s", strerror(errno));
		retval = 1;
		goto exit;
	}

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	memset(&usend_msg, 0x00, sizeof(struct udevd_msg));
	strcpy(usend_msg.magic, UDEV_MAGIC);
	usend_msg.type = UDEVD_UEVENT_UDEVSEND;

	/* copy all keys to send buffer */
	for (i = 0; envp[i]; i++) {
		const char *key;
		int keylen;

		key = envp[i];
		keylen = strlen(key);

		/* ignore events which are already sent on the netlink socket */
		if (strncmp(key, "SEQNUM=", 7) == 0) {
			dbg("ignoring event with SEQNUM set");
			retval = 0;
			goto exit;
		}

		/* prevent loops in the scripts we execute */
		if (strncmp(key, "UDEVD_EVENT=", 12) == 0) {
			err("event loop, already passed through the daemon, exit");
			retval = 2;
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

	usend_msg_len = offsetof(struct udevd_msg, envbuf) + bufpos;
	dbg("usend_msg_len=%i", usend_msg_len);

	if (sendto(sock, &usend_msg, usend_msg_len, 0, (struct sockaddr *)&saddr, addrlen) < 0) {
		retval = 3;
		err("error sending message: %s", strerror(errno));
	}

exit:
	if (sock != -1)
		close(sock);

	logging_close();
	return retval;
}
