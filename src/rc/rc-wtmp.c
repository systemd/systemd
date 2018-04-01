/*
 * rc-wtmp.c
 * This file contains routines to deal with the wtmp file.
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "rc-wtmp.h"

void log_wtmp(const char *user, const char *id, pid_t pid, int type,
		const char *line)
{
	struct timeval tv;
	struct utmp utmp;
	struct utsname uname_buf;

	memset(&utmp, 0, sizeof(utmp));
	gettimeofday(&tv, NULL);
	utmp.ut_tv.tv_sec = tv.tv_sec;
	utmp.ut_tv.tv_usec = tv.tv_usec;
	utmp.ut_pid  = pid;
	utmp.ut_type = type;
	strncpy(utmp.ut_name, user, sizeof(utmp.ut_name));
	strncpy(utmp.ut_id  , id  , sizeof(utmp.ut_id  ));
	strncpy(utmp.ut_line, line, sizeof(utmp.ut_line));
        
        /* Put the OS version in place of the hostname */
        if (uname(&uname_buf) == 0)
		strncpy(utmp.ut_host, uname_buf.release, sizeof(utmp.ut_host));

	updwtmp(WTMP_FILE, &utmp);
}
