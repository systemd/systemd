/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2006 Kay Sievers <kay.sievers@vrfy.org>
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>

#include "udev.h"
#include "udev_rules.h"
#include "udev_selinux.h"

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

static void asmlinkage sig_handler(int signum)
{
	switch (signum) {
		case SIGALRM:
			exit(1);
		case SIGINT:
		case SIGTERM:
			exit(20 + signum);
	}
}

int main(int argc, char *argv[], char *envp[])
{
	struct sysfs_device *dev;
	struct udevice *udev;
	const char *maj, *min;
	struct udev_rules rules;
	const char *action;
	const char *devpath;
	const char *subsystem;
	struct sigaction act;
	int devnull;
	int retval = -EINVAL;

	if (argc == 2 && strcmp(argv[1], "-V") == 0) {
		printf("%s\n", UDEV_VERSION);
		exit(0);
	}

	/* set std fd's to /dev/null, /sbin/hotplug forks us, we don't have them at all */
	devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0)  {
		if (devnull != STDIN_FILENO)
			dup2(devnull, STDIN_FILENO);
		if (devnull != STDOUT_FILENO)
			dup2(devnull, STDOUT_FILENO);
		if (devnull != STDERR_FILENO)
			dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	logging_init("udev");
	if (devnull < 0)
		err("open /dev/null failed: %s", strerror(errno));
	udev_config_init();
	selinux_init();
	dbg("version %s", UDEV_VERSION);

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = (void (*)(int)) sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_ALARM_TIMEOUT);

	action = getenv("ACTION");
	devpath = getenv("DEVPATH");
	subsystem = getenv("SUBSYSTEM");
	/* older kernels passed the SUBSYSTEM only as argument */
	if (subsystem == NULL && argc == 2)
		subsystem = argv[1];

	if (action == NULL || subsystem == NULL || devpath == NULL) {
		err("action, subsystem or devpath missing");
		goto exit;
	}

	/* export log_priority , as called programs may want to do the same as udev */
	if (udev_log_priority) {
		char priority[32];

		sprintf(priority, "%i", udev_log_priority);
		setenv("UDEV_LOG", priority, 1);
	}

	sysfs_init();
	udev_rules_init(&rules, 0);

	dev = sysfs_device_get(devpath);
	if (dev == NULL) {
		info("unable to open '%s'", devpath);
		goto fail;
	}

	udev = udev_device_init();
	if (udev == NULL)
		goto fail;

	/* override built-in sysfs device */
	udev->dev = dev;
	strlcpy(udev->action, action, sizeof(udev->action));

	/* get dev_t from environment, which is needed for "remove" to work, "add" works also from sysfs */
	maj = getenv("MAJOR");
	min = getenv("MINOR");
	if (maj != NULL && min != NULL)
		udev->devt = makedev(atoi(maj), atoi(min));
	else
		udev->devt = udev_device_get_devt(udev);

	retval = udev_device_event(&rules, udev);

	if (retval == 0 && !udev->ignore_device && udev_run) {
		struct name_entry *name_loop;

		dbg("executing run list");
		list_for_each_entry(name_loop, &udev->run_list, node) {
			if (strncmp(name_loop->name, "socket:", strlen("socket:")) == 0)
				pass_env_to_socket(&name_loop->name[strlen("socket:")], devpath, action);
			else {
				char program[PATH_SIZE];

				strlcpy(program, name_loop->name, sizeof(program));
				udev_rules_apply_format(udev, program, sizeof(program));
				run_program(program, udev->dev->subsystem, NULL, 0, NULL, (udev_log_priority >= LOG_INFO));
			}
		}
	}

	udev_device_cleanup(udev);
fail:
	udev_rules_cleanup(&rules);
	sysfs_cleanup();

exit:
	logging_close();
	if (retval != 0)
		return 1;
	return 0;
}
