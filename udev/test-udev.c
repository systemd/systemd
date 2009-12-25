/*
 * Copyright (C) 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <grp.h>

#include "udev.h"

static void sig_handler(int signum)
{
	switch (signum) {
		case SIGALRM:
			_exit(1);
		case SIGINT:
		case SIGTERM:
			_exit(20 + signum);
	}
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	struct udev_event *event;
	struct udev_device *dev;
	struct udev_rules *rules;
	char syspath[UTIL_PATH_SIZE];
	const char *devpath;
	const char *action;
	const char *subsystem;
	struct sigaction act;
	sigset_t mask;
	int err = -EINVAL;

	udev = udev_new();
	if (udev == NULL)
		exit(1);
	info(udev, "version %s\n", VERSION);
	udev_selinux_init(udev);

	/* set signal handlers */
	memset(&act, 0x00, sizeof(act));
	act.sa_handler = sig_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	/* trigger timeout to prevent hanging processes */
	alarm(UDEV_EVENT_TIMEOUT);

	action = getenv("ACTION");
	devpath = getenv("DEVPATH");
	subsystem = getenv("SUBSYSTEM");

	if (action == NULL || subsystem == NULL || devpath == NULL) {
		err(udev, "action, subsystem or devpath missing\n");
		goto exit;
	}

	rules = udev_rules_new(udev, 1);

	util_strscpyl(syspath, sizeof(syspath), udev_get_sys_path(udev), devpath, NULL);
	dev = udev_device_new_from_syspath(udev, syspath);
	if (dev == NULL) {
		info(udev, "unknown device '%s'\n", devpath);
		goto fail;
	}

	/* skip reading of db, but read kernel parameters */
	udev_device_set_info_loaded(dev);
	udev_device_read_uevent_file(dev);

	udev_device_set_action(dev, action);
	event = udev_event_new(dev);
	err = udev_event_execute_rules(event, rules);

	/* rules may change/disable the timeout */
	if (udev_device_get_event_timeout(dev) >= 0)
		alarm(udev_device_get_event_timeout(dev));

	if (err == 0)
		udev_event_execute_run(event, NULL);

	udev_event_unref(event);
	udev_device_unref(dev);
fail:
	udev_rules_unref(rules);
exit:
	udev_selinux_exit(udev);
	udev_unref(udev);
	if (err != 0)
		return 1;
	return 0;
}
