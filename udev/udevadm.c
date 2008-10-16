/*
 * Copyright (C) 2007-2008 Kay Sievers <kay.sievers@vrfy.org>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "udev.h"

static int debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "%s: ", fn);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

struct command {
	const char *name;
	int (*cmd)(struct udev *udev, int argc, char *argv[]);
	const char *help;
	int debug;
};

static const struct command cmds[];

static int version(struct udev *udev, int argc, char *argv[])
{
	printf("%s\n", VERSION);
	return 0;
}

static int help(struct udev *udev, int argc, char *argv[])
{
	const struct command *cmd;

	printf("Usage: udevadm [--help] [--version] [--debug] COMMAND [COMMAND OPTIONS]\n");
	for (cmd = cmds; cmd->name != NULL; cmd++)
		if (cmd->help != NULL)
			printf("  %-12s %s\n", cmd->name, cmd->help);
	printf("\n");
	return 0;
}

static const struct command cmds[] = {
	{
		.name = "info",
		.cmd = udevadm_info,
		.help = "query sysfs or the udev database",
	},
	{
		.name = "trigger",
		.cmd = udevadm_trigger,
		.help = "request events from the kernel",
	},
	{
		.name = "settle",
		.cmd = udevadm_settle, "",
		.help = "wait for the event queue to finish",
	},
	{
		.name = "control",
		.cmd = udevadm_control,
		.help = "control the udev daemon",
	},
	{
		.name = "monitor",
		.cmd = udevadm_monitor,
		.help = "listen to kernel and udev events",
	},
	{
		.name = "test",
		.cmd = udevadm_test,
		.help = "simulation run",
		.debug = 1,
	},
	{
		.name = "version",
		.cmd = version,
	},
	{
		.name = "help",
		.cmd = help,
	},
	{}
};

static int run_command(struct udev *udev, const struct command *cmd, int argc, char *argv[])
{
	if (cmd->debug) {
		debug = 1;
		if (udev_get_log_priority(udev) < LOG_INFO)
			udev_set_log_priority(udev, LOG_INFO);
	}
	info(udev, "calling: %s\n", cmd->name);
	return cmd->cmd(udev, argc, argv);
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	static const struct option options[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{}
	};
	const char *command;
	int i;
	const char *pos;
	int rc = 1;

	udev = udev_new();
	if (udev == NULL)
		goto out;

	logging_init("udevadm");
	udev_set_log_fn(udev, log_fn);
	selinux_init(udev);

	/* see if we are a compat link, this will be removed in a future release */
	command = argv[0];
	pos = strrchr(command, '/');
	if (pos != NULL)
		command = &pos[1];

	/* the trailing part of the binary or link name is the command */
	if (strncmp(command, "udev", 4) == 0)
		command = &command[4];

	for (i = 0; cmds[i].cmd != NULL; i++) {
		if (strcmp(cmds[i].name, command) == 0) {
			char path[128];
			char prog[512];
			ssize_t len;

			snprintf(path, sizeof(path), "/proc/%lu/exe", (unsigned long) getppid());
			len = readlink(path, prog, sizeof(prog));
			if (len > 0) {
				prog[len] = '\0';
				fprintf(stderr, "the program '%s' called '%s', it should use 'udevadm %s <options>', "
				       "this will stop working in a future release\n", prog, argv[0], command);
				err(udev, "the program '%s' called '%s', it should use 'udevadm %s <options>', "
				    "this will stop working in a future release\n", prog, argv[0], command);
			}
			rc = run_command(udev, &cmds[i], argc, argv);
			goto out;
		}
	}

	while (1) {
		int option;

		option = getopt_long(argc, argv, "+dhV", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'h':
			rc = help(udev, argc, argv);
			goto out;
		case 'V':
			rc = version(udev, argc, argv);
			goto out;
		default:
			goto out;
		}
	}
	command = argv[optind];

	if (command != NULL)
		for (i = 0; cmds[i].cmd != NULL; i++) {
			if (strcmp(cmds[i].name, command) == 0) {
				optind++;
				rc = run_command(udev, &cmds[i], argc, argv);
				goto out;
			}
		}

	fprintf(stderr, "missing or unknown command\n\n");
	help(udev, argc, argv);
	rc = 2;
out:
	selinux_exit(udev);
	udev_unref(udev);
	logging_close();
	return rc;
}
