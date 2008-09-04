/*
 * Copyright (C) 2007 Kay Sievers <kay.sievers@vrfy.org>
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

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "udev.h"

static int debug;

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list	args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	if (debug)
		vprintf(format, args);
	else
		vsyslog(priority, format, args);
	va_end(args);
}
#endif

struct command {
	const char *name;
	int (*cmd)(int argc, char *argv[]);
	const char *help;
	int debug;
};

static const struct command cmds[];

static int version(int argc, char *argv[])
{
	printf("%s\n", VERSION);
	return 0;
}

static int help(int argc, char *argv[])
{
	const struct command *cmd;

	printf("Usage: udevadm COMMAND [OPTIONS]\n");
	for (cmd = cmds; cmd->name != NULL; cmd++)
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
		.help = "print the version number",
	},
	{
		.name = "help",
		.cmd = help,
		.help = "print this help text",
	},
	{}
};

int main(int argc, char *argv[])
{
	const char *command = argv[1];
	int i;
	const char *pos;
	int rc;

	logging_init("udevadm");
	udev_config_init();
	sysfs_init();

	/* find command */
	if (command != NULL)
		for (i = 0; cmds[i].cmd != NULL; i++) {
			if (strcmp(cmds[i].name, command) == 0) {
				debug = cmds[i].debug;
				rc = cmds[i].cmd(argc-1, &argv[1]);
				goto out;
			}
		}

	/* try to find compat link, will be removed in a future release */
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
				info("the program '%s' called '%s', it should use 'udevadm %s <options>', "
				     "this will stop working in a future release\n", prog, argv[0], command);
			}
			debug = cmds[i].debug;
			rc = cmds[i].cmd(argc, argv);
			goto out;
		}
	}

	fprintf(stderr, "unknown command, try help\n\n");
	rc = 2;
out:
	sysfs_cleanup();
	logging_close();
	return rc;
}
