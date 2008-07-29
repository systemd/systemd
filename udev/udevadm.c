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
	int (*cmd)(int argc, char *argv[], char *envp[]);
	const char *help;
	int debug;
};

static const struct command cmds[];

static int version(int argc, char *argv[], char *envp[])
{
	printf("%s\n", VERSION);
	return 0;
}

static int help(int argc, char *argv[], char *envp[])
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
		.cmd = udevinfo,
		.help = "query sysfs or the udev database",
	},
	{
		.name = "trigger",
		.cmd = udevtrigger,
		.help = "request events from the kernel",
	},
	{
		.name = "settle",
		.cmd = udevsettle, "",
		.help = "wait for the event queue to finish",
	},
	{
		.name = "control",
		.cmd = udevcontrol,
		.help = "control the udev daemon",
	},
	{
		.name = "monitor",
		.cmd = udevmonitor,
		.help = "listen to kernel and udev events",
	},
	{
		.name = "test",
		.cmd = udevtest,
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

int main(int argc, char *argv[], char *envp[])
{
	const char *command;
	const char *pos;
	const struct command *cmd;
	int rc;

	/* get binary or symlink name */
	pos = strrchr(argv[0], '/');
	if (pos != NULL)
		command = &pos[1];
	else
		command = argv[0];

	/* the trailing part of the binary or symlink name is the command */
	if (strncmp(command, "udev", 4) == 0)
		command = &command[4];

	if (command == NULL || command[0] == '\0')
		goto err_unknown;

	/* udevadm itself needs to strip its name from the passed options */
	if (strcmp(command, "adm") == 0) {
		command = argv[1];
		argv++;
		argc--;
	}

	if (command == NULL)
		goto err_unknown;

	/* allow command to be specified as an option */
	if (strncmp(command, "--", 2) == 0)
		command += 2;

	/* find and execute command */
	for (cmd = cmds; cmd->name != NULL; cmd++) {
		if (strcmp(cmd->name, command) == 0) {
			debug = cmd->debug;
			rc = cmd->cmd(argc, argv, envp);
			goto out;
		}
	}

err_unknown:
	fprintf(stderr, "unknown command, try help\n\n");
	rc = 2;
out:
	return rc;
}
