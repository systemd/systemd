/*
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
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

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "udev.h"
#include "udevd.h"

static int sock = -1;
static int udev_log = 0;

#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list	args;

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	static struct udevd_ctrl_msg ctrl_msg;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	const char *env;
	const char *val;
	int *intval;
	int i;
	int retval = 1;

	env = getenv("UDEV_LOG");
	if (env)
		udev_log = log_priority(env);

	logging_init("udevcontrol");
	dbg("version %s", UDEV_VERSION);

	if (argc < 2) {
		fprintf(stderr, "missing command\n\n");
		goto exit;
	}

	memset(&ctrl_msg, 0x00, sizeof(struct udevd_ctrl_msg));
	strcpy(ctrl_msg.magic, UDEVD_CTRL_MAGIC);

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "stop_exec_queue"))
			ctrl_msg.type = UDEVD_CTRL_STOP_EXEC_QUEUE;
		else if (!strcmp(arg, "start_exec_queue"))
			ctrl_msg.type = UDEVD_CTRL_START_EXEC_QUEUE;
		else if (!strcmp(arg, "reload_rules"))
			ctrl_msg.type = UDEVD_CTRL_RELOAD_RULES;
		else if (!strncmp(arg, "log_priority=", strlen("log_priority="))) {
			intval = (int *) ctrl_msg.buf;
			val = &arg[strlen("log_priority=")];
			ctrl_msg.type = UDEVD_CTRL_SET_LOG_LEVEL;
			*intval = log_priority(val);
			info("send log_priority=%i", *intval);
		} else if (!strncmp(arg, "max_childs=", strlen("max_childs="))) {
			char *endp;
			int count;

			intval = (int *) ctrl_msg.buf;
			val = &arg[strlen("max_childs=")];
			ctrl_msg.type = UDEVD_CTRL_SET_MAX_CHILDS;
			count = strtoul(val, &endp, 0);
			if (endp[0] != '\0' || count < 1) {
				fprintf(stderr, "invalid number\n");
				goto exit;
			}
			*intval = count;
			info("send max_childs=%i", *intval);
		} else if (!strncmp(arg, "max_childs_running=", strlen("max_childs_running="))) {
			char *endp;
			int count;

			intval = (int *) ctrl_msg.buf;
			val = &arg[strlen("max_childs_running=")];
			ctrl_msg.type = UDEVD_CTRL_SET_MAX_CHILDS_RUNNING;
			count = strtoul(val, &endp, 0);
			if (endp[0] != '\0' || count < 1) {
				fprintf(stderr, "invalid number\n");
				goto exit;
			}
			*intval = count;
			info("send max_childs_running=%i", *intval);
		} else if (strcmp(arg, "help") == 0  || strcmp(arg, "--help") == 0  || strcmp(arg, "-h") == 0) {
			printf("Usage: udevcontrol COMMAND\n"
				"  log_priority=<level>   set the udev log level for the daemon\n"
				"  stop_exec_queue        keep udevd from executing events, queue only\n"
				"  start_exec_queue       execute events, flush queue\n"
				"  reload_rules           reloads the rules files\n"
				"  max_childs=<N>         maximum number of childs\n"
				"  max_childs_running=<N> maximum number of childs running at the same time\n"
				"  --help                 print this help text\n\n");
			goto exit;
		} else {
			fprintf(stderr, "unrecognized command '%s'\n", arg);
			goto exit;
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "root privileges required\n");
		goto exit;
	}

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		err("error getting socket: %s", strerror(errno));
		goto exit;
	}

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_CTRL_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	retval = sendto(sock, &ctrl_msg, sizeof(ctrl_msg), 0, (struct sockaddr *)&saddr, addrlen);
	if (retval == -1) {
		err("error sending message: %s", strerror(errno));
		retval = 1;
	} else {
		dbg("sent message type=0x%02x, %u bytes sent", ctrl_msg.type, retval);
		retval = 0;
	}

	close(sock);
exit:
	logging_close();
	return retval;
}
