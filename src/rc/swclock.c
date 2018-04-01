/*
 * swclock.c
 * Sets the system time from the mtime of the given file.
 * This is useful for systems who do not have a working RTC and rely on ntp.
 * OpenRC relies on the correct system time for a lot of operations
 * so this is needed quite early.
 */

/*
 * Copyright (c) 2007-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <utime.h>

#include "einfo.h"
#include "rc.h"
#include "rc-misc.h"
#include "_usage.h"

#define RC_SHUTDOWNTIME    RC_SVCDIR "/shutdowntime"

const char *applet = NULL;
const char *extraopts = "file";
const char *getoptstring = "sw" getoptstring_COMMON;
const struct option longopts[] = {
	{ "save", 0, NULL, 's' },
	{ "warn", 0, NULL, 'w' },
	longopts_COMMON
};
const char * const longopts_help[] = {
	"saves the time",
	"no error if no reference file",
	longopts_help_COMMON
};
const char *usagestring = NULL;

int main(int argc, char **argv)
{
	int opt, sflag = 0, wflag = 0;
	const char *file = RC_SHUTDOWNTIME;
	struct stat sb;
	struct timeval tv;

	applet = basename_c(argv[0]);
	while ((opt = getopt_long(argc, argv, getoptstring,
		    longopts, (int *) 0)) != -1)
	{
		switch (opt) {
		case 's':
			sflag = 1;
			break;
		case 'w':
			wflag = 1;
			break;
		case_RC_COMMON_GETOPT
		}
	}

	if (optind < argc)
		file = argv[optind++];

	if (sflag) {
		if (stat(file, &sb) == -1) {
			opt = open(file, O_WRONLY | O_CREAT, 0644);
			if (opt == -1)
				eerrorx("swclock: open: %s", strerror(errno));
			close(opt);
		} else
			if (utime(file, NULL) == -1)
				eerrorx("swclock: utime: %s", strerror(errno));
		return 0;
	}

	if (stat(file, &sb) == -1) {
		if (wflag != 0 && errno == ENOENT)
			ewarn("swclock: `%s': %s", file, strerror(errno));
		else
			eerrorx("swclock: `%s': %s", file, strerror(errno));
		return 0;
	}

	tv.tv_sec = sb.st_mtime;
	tv.tv_usec = 0;

	if (settimeofday(&tv, NULL) == -1)
		eerrorx("swclock: settimeofday: %s", strerror(errno));

	return 0;
}
