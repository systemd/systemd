/*
 * openrc-shutdown.c
 * If you are using OpenRC's provided init, this will shut down or
 * reboot your system.
 *
 * This is based on code written by James Hammons <jlhamm@acm.org>, so
 * I would like to publically thank him for his work.
 */

/*
 * Copyright 2017 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "einfo.h"
#include "rc.h"
#include "helpers.h"
#include "_usage.h"
#include "rc-wtmp.h"

const char *applet = NULL;
const char *extraopts = NULL;
const char *getoptstring = "dDHKpRrsw" getoptstring_COMMON;
const struct option longopts[] = {
	{ "no-write",        no_argument, NULL, 'd'},
	{ "dry-run",        no_argument, NULL, 'D'},
	{ "halt",        no_argument, NULL, 'H'},
	{ "kexec",        no_argument, NULL, 'K'},
	{ "poweroff",        no_argument, NULL, 'p'},
	{ "reexec",        no_argument, NULL, 'R'},
	{ "reboot",        no_argument, NULL, 'r'},
	{ "single",        no_argument, NULL, 's'},
	{ "write-only",        no_argument, NULL, 'w'},
	longopts_COMMON
};
const char * const longopts_help[] = {
	"do not write wtmp record",
	"print actions instead of executing them",
	"halt the system",
	"reboot the system using kexec",
	"power off the system",
	"re-execute init (use after upgrading)",
	"reboot the system",
	"single user mode",
	"write wtmp boot record and exit",
	longopts_help_COMMON
};
const char *usagestring = NULL;
const char *exclusive = "Select one of "
"--halt, --kexec, --poweroff, --reexec, --reboot, --single or --write-only";

static bool do_dryrun = false;
static bool do_halt = false;
static bool do_kexec = false;
static bool do_poweroff = false;
static bool do_reboot = false;
static bool do_reexec = false;
static bool do_single = false;
static bool do_wtmp = true;
static bool do_wtmp_only = false;

static void send_cmd(const char *cmd)
{
	FILE *fifo;
 	size_t ignored;

	if (do_dryrun) {
		einfo("Would send %s to init", cmd);
		return;
	}
	if (do_wtmp && (do_halt || do_kexec || do_reboot || do_poweroff))
		log_wtmp("shutdown", "~~", 0, RUN_LVL, "~~");
	fifo = fopen(RC_INIT_FIFO, "w");
	if (!fifo) {
		perror("fopen");
		return;
	}

	ignored = fwrite(cmd, 1, strlen(cmd), fifo);
	if (ignored != strlen(cmd))
		printf("Error writing to init fifo\n");
	fclose(fifo);
}

int main(int argc, char **argv)
{
	int opt;
	int cmd_count = 0;

	applet = basename_c(argv[0]);
	while ((opt = getopt_long(argc, argv, getoptstring,
		    longopts, (int *) 0)) != -1)
	{
		switch (opt) {
			case 'd':
				do_wtmp = false;
				break;
		case 'D':
			do_dryrun = true;
			break;
		case 'H':
			do_halt = true;
			cmd_count++;
			break;
		case 'K':
			do_kexec = true;
			cmd_count++;
			break;
		case 'p':
			do_poweroff = true;
			cmd_count++;
			break;
		case 'R':
			do_reexec = true;
			cmd_count++;
			break;
		case 'r':
			do_reboot = true;
			cmd_count++;
			break;
		case 's':
			do_single = true;
			cmd_count++;
			break;
		case 'w':
			do_wtmp_only = true;
			cmd_count++;
			break;
		case_RC_COMMON_GETOPT
		}
	}
	if (geteuid() != 0 && ! do_dryrun)
		eerrorx("%s: you must be root\n", applet);
	if (cmd_count != 1) {
		eerror("%s: %s\n", applet, exclusive);
		usage(EXIT_FAILURE);
	}
	if (do_halt)
		send_cmd("halt");
	else if (do_kexec)
		send_cmd("kexec");
	else if (do_poweroff)
		send_cmd("poweroff");
	else if (do_reboot)
		send_cmd("reboot");
	else if (do_reexec)
		send_cmd("reexec");
	else if (do_wtmp_only)
		log_wtmp("shutdown", "~~", 0, RUN_LVL, "~~");
	else if (do_single)
		send_cmd("single");
	return 0;
}
