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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>

#include "udev.h"
#include "udev_rules.h"


#ifdef USE_LOG
void log_message (int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
}
#endif

static int import_uevent_var(const char *devpath)
{
	char path[PATH_SIZE];
	static char value[4096]; /* must stay, used with putenv */
	ssize_t size;
	int fd;
	char *key;
	char *next;
	int rc = -1;

	/* read uevent file */
	strlcpy(path, sysfs_path, sizeof(path));
	strlcat(path, devpath, sizeof(path));
	strlcat(path, "/uevent", sizeof(path));
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;
	size = read(fd, value, sizeof(value));
	close(fd);
	if (size < 0)
		goto out;
	value[size] = '\0';

	/* import keys into environment */
	key = value;
	while (key[0] != '\0') {
		next = strchr(key, '\n');
		if (next == NULL)
			goto out;
		next[0] = '\0';
		info("import into environment: '%s'", key);
		putenv(key);
		key = &next[1];
	}
	rc = 0;
out:
	return rc;
}

int main(int argc, char *argv[], char *envp[])
{
	int force = 0;
	char *action = "add";
	char *subsystem = NULL;
	char *devpath = NULL;
	struct udevice *udev;
	struct sysfs_device *dev;
	struct udev_rules rules = {};
	int retval;
	int rc = 0;

	static const struct option options[] = {
		{ "action", 1, NULL, 'a' },
		{ "subsystem", 1, NULL, 's' },
		{ "force", 0, NULL, 'f' },
		{ "help", 0, NULL, 'h' },
		{}
	};

	info("version %s", UDEV_VERSION);
	udev_config_init();
	if (udev_log_priority < LOG_INFO) {
		char priority[32];

		udev_log_priority = LOG_INFO;
		sprintf(priority, "%i", udev_log_priority);
		setenv("UDEV_LOG", priority, 1);
	}

	while (1) {
		int option;

		option = getopt_long(argc, argv, "a:s:fh", options, NULL);
		if (option == -1)
			break;

		dbg("option '%c'", option);
		switch (option) {
		case 'a':
			action = optarg;
			break;
		case 's':
			subsystem = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'h':
			printf("Usage: udevtest OPTIONS <devpath>\n"
			       "  --action=<string>     set action string\n"
			       "  --subsystem=<string>  set subsystem string\n"
			       "  --force               don't skip node/link creation\n"
			       "  --help                print this help text\n\n");
			exit(0);
		default:
			exit(1);
		}
	}
	devpath = argv[optind];

	if (devpath == NULL) {
		fprintf(stderr, "devpath parameter missing\n");
		rc = 1;
		goto exit;
	}

	printf("This program is for debugging only, it does not run any program,\n"
	       "specified by a RUN key. It may show incorrect results, because\n"
	       "some values may be different, or not available at a simulation run.\n"
	       "\n");

	sysfs_init();
	udev_rules_init(&rules, 0);

	/* remove /sys if given */
	if (strncmp(devpath, sysfs_path, strlen(sysfs_path)) == 0)
		devpath = &devpath[strlen(sysfs_path)];

	dev = sysfs_device_get(devpath);
	if (dev == NULL) {
		fprintf(stderr, "unable to open device '%s'\n", devpath);
		rc = 2;
		goto exit;
	}

	udev = udev_device_init(NULL);
	if (udev == NULL) {
		fprintf(stderr, "error initializing device\n");
		rc = 3;
		goto exit;
	}

	if (subsystem != NULL)
		strlcpy(dev->subsystem, subsystem, sizeof(dev->subsystem));

	/* override built-in sysfs device */
	udev->dev = dev;
	strlcpy(udev->action, action, sizeof(udev->action));
	udev->devt = udev_device_get_devt(udev);

	/* simulate node creation with test flag */
	if (!force)
		udev->test_run = 1;

	setenv("DEVPATH", udev->dev->devpath, 1);
	setenv("SUBSYSTEM", udev->dev->subsystem, 1);
	setenv("ACTION", udev->action, 1);
	import_uevent_var(udev->dev->devpath);

	info("looking at device '%s' from subsystem '%s'", udev->dev->devpath, udev->dev->subsystem);
	retval = udev_device_event(&rules, udev);
	if (retval == 0 && !udev->ignore_device && udev_run) {
		struct name_entry *name_loop;

		list_for_each_entry(name_loop, &udev->run_list, node) {
			char program[PATH_SIZE];

			strlcpy(program, name_loop->name, sizeof(program));
			udev_rules_apply_format(udev, program, sizeof(program));
			info("run: '%s'", program);
		}
	}
	udev_device_cleanup(udev);

exit:
	udev_rules_cleanup(&rules);
	sysfs_cleanup();
	return rc;
}
