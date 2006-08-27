/*
 * Copyright (C) 2006 Kay Sievers <kay@vrfy.org>
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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "udev.h"
#include "udevd.h"

#define DEFAULT_TIMEOUT			180
#define LOOP_PER_SECOND			20


#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
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
	char queuename[PATH_SIZE];
	char filename[PATH_SIZE];
	unsigned long long seq_kernel;
	unsigned long long seq_udev;
	char seqnum[32];
	int fd;
	ssize_t len;
	int timeout = DEFAULT_TIMEOUT;
	int loop;
	int i;
	int rc = 1;

	logging_init("udevsettle");
	udev_config_init();
	dbg("version %s", UDEV_VERSION);
	sysfs_init();

	for (i = 1 ; i < argc; i++) {
		char *arg = argv[i];

		if (strncmp(arg, "--timeout=", 10) == 0) {
			char *str = &arg[10];
			int seconds;

			seconds = atoi(str);
			if (seconds > 0)
				timeout = seconds;
			else
				fprintf(stderr, "invalid timeout value\n");
			dbg("timeout=%i", timeout);
		} else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
			printf("Usage: udevsettle [--help] [--timeout=<seconds>]\n");
			goto exit;
		} else {
			fprintf(stderr, "unrecognized option '%s'\n", arg);
			err("unrecognized option '%s'\n", arg);
		}
	}

	strlcpy(queuename, udev_root, sizeof(queuename));
	strlcat(queuename, "/" EVENT_QUEUE_DIR, sizeof(queuename));

	loop = timeout * LOOP_PER_SECOND;
	while (loop--) {
		/* wait for events in queue to finish */
		while (loop--) {
			struct stat statbuf;

			if (stat(queuename, &statbuf) < 0) {
				info("queue is empty");
				break;
			}
			usleep(1000 * 1000 / LOOP_PER_SECOND);
		}
		if (loop <= 0) {
			info("timeout waiting for queue");
			goto exit;
		}

		/* read current kernel seqnum */
		strlcpy(filename, sysfs_path, sizeof(filename));
		strlcat(filename, "/kernel/uevent_seqnum", sizeof(filename));
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			goto exit;
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
		if (len <= 0)
			goto exit;
		seqnum[len] = '\0';
		seq_kernel = strtoull(seqnum, NULL, 10);
		info("kernel seqnum = %llu", seq_kernel);

		/* read current udev seqnum */
		strlcpy(filename, udev_root, sizeof(filename));
		strlcat(filename, "/" EVENT_SEQNUM, sizeof(filename));
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			goto exit;
		len = read(fd, seqnum, sizeof(seqnum)-1);
		close(fd);
		if (len <= 0)
			goto exit;
		seqnum[len] = '\0';
		seq_udev = strtoull(seqnum, NULL, 10);
		info("udev seqnum = %llu", seq_udev);

		/* make sure all kernel events have arrived in the queue */
		if (seq_udev >= seq_kernel) {
			info("queue is empty and no pending events left");
			rc = 0;
			goto exit;
		}
		usleep(1000 * 1000 / LOOP_PER_SECOND);
		info("queue is empty, but events still pending");
	}

exit:
	sysfs_cleanup();
	logging_close();
	return rc;
}
