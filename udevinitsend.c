/*
 * udevinitsend.c
 *
 * Userspace devfs
 *
 * Copyright (C) 2004, 2005 Hannes Reinecke <hare@suse.de>
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <dirent.h>

#include "udev.h"
#include "udev_version.h"
#include "udevd.h"
#include "udev_utils.h"
#include "logging.h"

static int log = 0;

#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list	args;

	if (priority > log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

/*
 * udevsend
 *
 * Scan a file, write all variables into the msgbuf and
 * fires the message to udevd.
 */
static int udevsend(char *filename, int sock, int disable_loop_detection)
{
	static struct udevd_msg usend_msg;
	int usend_msg_len;
	int bufpos = 0;
	struct stat statbuf;
	int fd;
	char *fdmap, *ls, *le, *ch;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	int retval = 0;

	if (stat(filename,&statbuf) < 0) {
		dbg("cannot stat %s: %s\n", filename, strerror(errno));
		return 1;
	}
	fd = open(filename,O_RDONLY);
	if (fd < 0)
		return 1;

	fdmap = mmap(0, statbuf.st_size,
		     PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (fdmap == MAP_FAILED) {
		dbg("mmap failed, errno %d\n", errno);
		return 1;
	}

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* use abstract namespace for socket path */
	strcpy(&saddr.sun_path[1], UDEVD_SOCK_PATH);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	memset(&usend_msg, 0x00, sizeof(struct udevd_msg));
	strcpy(usend_msg.magic, UDEV_MAGIC);
	usend_msg.type = UDEVD_UEVENT_INITSEND;

	ls = fdmap;
	ch = le = ls;
	while (*ch && ch < fdmap + statbuf.st_size) {
		le = strchr(ch, '\n');
		if (!le)
			break;
		ch = strchr(ch, '=');
		if (!ch)
			break;

		/* prevent loops in the scripts we execute */
		if (strncmp(ls, "UDEVD_EVENT=", 12) == 0) {
			if (!disable_loop_detection) {
				dbg("event already handled by udev\n");
				retval = -1;
				break;
			} 
			goto loop_end;
		}

		/* omit shell-generated keys */
		if (ls[0] == '_' && ls[1] == '=') {
			goto loop_end;
		}

		if (ch < le) {

			strncpy(&usend_msg.envbuf[bufpos],ls,(ch - ls) + 1);
			bufpos += (ch - ls) + 1;
			if (ch[1] == '\'' && le[-1] == '\'') {
				strncpy(&usend_msg.envbuf[bufpos],ch + 2, (le - ch) -3);
				bufpos += (le - ch) - 3;
			} else {
				strncpy(&usend_msg.envbuf[bufpos],ch, (le - ch));
				bufpos += (le - ch);
			}
			bufpos++;
		}
loop_end:
		ch = le + 1;
		ls = ch;
	}
	munmap(fdmap, statbuf.st_size);

	usend_msg_len = offsetof(struct udevd_msg, envbuf) + bufpos;
	dbg("usend_msg_len=%i", usend_msg_len);

	if (!retval) {
		retval = sendto(sock, &usend_msg, usend_msg_len, 0, (struct sockaddr *)&saddr, addrlen);
		if (retval < 0) {
			dbg("error sending message (%s)", strerror(errno));
		}
	}
		
	return retval;
}

int main(int argc, char *argv[], char *envp[])
{
	static const char short_options[] = "d:f:lVh";
	int option;
	char *event_dir = NULL;
	char *event_file = NULL;
	DIR *dirstream;
	struct dirent *direntry;
	int retval = 1;
	int disable_loop_detection = 0;
	int sock;
	const char *env;

	env = getenv("UDEV_LOG");
	if (env)
		log = log_priority(env);

	logging_init("udevinitsend");
	dbg("version %s", UDEV_VERSION);

	/* get command line options */
	while (1) {
		option = getopt(argc, argv, short_options);
		if (option == -1)
			break;

		dbg("option '%c': ", option);
		switch (option) {
		case 'd':
			dbg("scan directory %s\n", optarg);
			event_dir = optarg;
			break;

		case 'f':
			dbg("use event file %s\n", optarg);
			event_file = optarg;
			break;

		case 'l':
			dbg("disable loop detection, ignore UDEVD_EVENT\n");
			disable_loop_detection = 1;
			break;

		case 'h':
			retval = 0;
		}
	}

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		dbg("error getting socket");
		return 1;
	}

	if (event_dir) {
		dirstream = opendir(event_dir);
		if (!dirstream) {
			info("error opening directory %s: %s\n",
			     event_dir, strerror(errno));
			return 1;
		}
		chdir(event_dir);
		while ((direntry = readdir(dirstream)) != NULL) {
			if (!strcmp(direntry->d_name,".") ||
			    !strcmp(direntry->d_name,".."))
				continue;
			retval = udevsend(direntry->d_name, sock, disable_loop_detection);
		}
		closedir(dirstream);
	} else if (event_file) {
		retval = udevsend(event_file, sock, disable_loop_detection);
	}

	if (sock != -1)
		close(sock);

	return retval;
}
