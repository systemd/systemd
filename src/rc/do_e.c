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

#define SYSLOG_NAMES

#include <sys/types.h>
#include <sys/time.h>

#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "einfo.h"
#include "helpers.h"

/* usecs to wait while we poll the file existance  */
#define WAIT_INTERVAL	20000000

const char *applet = NULL;

static int syslog_decode(char *name, CODE *codetab)
{
	CODE *c;

	if (isdigit((unsigned char)*name))
		return atoi(name);

	for (c = codetab; c->c_name; c++)
		if (! strcasecmp(name, c->c_name))
			return c->c_val;

	return -1;
}

int main(int argc, char **argv)
{
	int retval = EXIT_SUCCESS;
	int i;
	size_t l = 0;
	char *message = NULL;
	char *p;
	int level = 0;
	struct timespec ts;
	struct timeval stop, now;
	int (*e) (const char *, ...) EINFO_PRINTF(1, 2) = NULL;
	int (*ee) (int, const char *, ...) EINFO_PRINTF(2, 3) = NULL;

	applet = basename_c(argv[0]);
	argc--;
	argv++;

	if (strcmp(applet, "eval_ecolors") == 0) {
		printf("GOOD='%s'\nWARN='%s'\nBAD='%s'\nHILITE='%s'\nBRACKET='%s'\nNORMAL='%s'\n",
		    ecolor(ECOLOR_GOOD),
		    ecolor(ECOLOR_WARN),
		    ecolor(ECOLOR_BAD),
		    ecolor(ECOLOR_HILITE),
		    ecolor(ECOLOR_BRACKET),
		    ecolor(ECOLOR_NORMAL));
		exit(EXIT_SUCCESS);
	}

	if (argc > 0) {
		if (strcmp(applet, "eend") == 0 ||
		    strcmp(applet, "ewend") == 0 ||
		    strcmp(applet, "veend") == 0 ||
		    strcmp(applet, "vweend") == 0 ||
		    strcmp(applet, "ewaitfile") == 0)
		{
			errno = 0;
			retval = (int)strtoimax(argv[0], &p, 0);
			if (!p || *p != '\0')
				errno = EINVAL;
			if (errno)
				retval = EXIT_FAILURE;
			else {
				argc--;
				argv++;
			}
		} else if (strcmp(applet, "esyslog") == 0 ||
		    strcmp(applet, "elog") == 0) {
			p = strchr(argv[0], '.');
			if (!p ||
			    (level = syslog_decode(p + 1, prioritynames)) == -1)
				eerrorx("%s: invalid log level `%s'", applet, argv[0]);

			if (argc < 3)
				eerrorx("%s: not enough arguments", applet);

			unsetenv("EINFO_LOG");
			setenv("EINFO_LOG", argv[1], 1);

			argc -= 2;
			argv += 2;
		}
	}

	if (strcmp(applet, "ewaitfile") == 0) {
		if (errno)
			eerrorx("%s: invalid timeout", applet);
		if (argc == 0)
			eerrorx("%s: not enough arguments", applet);

		gettimeofday(&stop, NULL);
		/* retval stores the timeout */
		stop.tv_sec += retval;
		ts.tv_sec = 0;
		ts.tv_nsec = WAIT_INTERVAL;
		for (i = 0; i < argc; i++) {
			ebeginv("Waiting for %s", argv[i]);
			for (;;) {
				if (exists(argv[i]))
					break;
				if (nanosleep(&ts, NULL) == -1)
					return EXIT_FAILURE;
				gettimeofday(&now, NULL);
				if (retval <= 0)
					continue;
				if (timercmp(&now, &stop, <))
					continue;
				eendv(EXIT_FAILURE,
				    "timed out waiting for %s", argv[i]);
				return EXIT_FAILURE;
			}
			eendv(EXIT_SUCCESS, NULL);
		}
		return EXIT_SUCCESS;
	}

	if (argc > 0) {
		for (i = 0; i < argc; i++)
			l += strlen(argv[i]) + 1;

		message = xmalloc(l);
		p = message;

		for (i = 0; i < argc; i++) {
			if (i > 0)
				*p++ = ' ';
			l = strlen(argv[i]);
			memcpy(p, argv[i], l);
			p += l;
		}
		*p = 0;
	}

	if (strcmp(applet, "einfo") == 0)
		e = einfo;
	else if (strcmp(applet, "einfon") == 0)
		e = einfon;
	else if (strcmp(applet, "ewarn") == 0)
		e = ewarn;
	else if (strcmp(applet, "ewarnn") == 0)
		e = ewarnn;
	else if (strcmp(applet, "eerror") == 0) {
		e = eerror;
		retval = 1;
	} else if (strcmp(applet, "eerrorn") == 0) {
		e = eerrorn;
		retval = 1;
	} else if (strcmp(applet, "ebegin") == 0)
		e = ebegin;
	else if (strcmp(applet, "eend") == 0)
		ee = eend;
	else if (strcmp(applet, "ewend") == 0)
		ee = ewend;
	else if (strcmp(applet, "esyslog") == 0) {
		elog(retval, "%s", message);
		retval = 0;
	} else if (strcmp(applet, "veinfo") == 0)
		e = einfov;
	else if (strcmp(applet, "veinfon") == 0)
		e = einfovn;
	else if (strcmp(applet, "vewarn") == 0)
		e = ewarnv;
	else if (strcmp(applet, "vewarnn") == 0)
		e = ewarnvn;
	else if (strcmp(applet, "vebegin") == 0)
		e = ebeginv;
	else if (strcmp(applet, "veend") == 0)
		ee = eendv;
	else if (strcmp(applet, "vewend") == 0)
		ee = ewendv;
	else if (strcmp(applet, "eindent") == 0)
		eindent();
	else if (strcmp(applet, "eoutdent") == 0)
		eoutdent();
	else if (strcmp(applet, "veindent") == 0)
		eindentv();
	else if (strcmp(applet, "veoutdent") == 0)
		eoutdentv();
	else {
		eerror("%s: unknown applet", applet);
		retval = EXIT_FAILURE;
	}

	if (message) {
		if (e)
			e("%s", message);
		else if (ee)
			ee(retval, "%s", message);
	} else {
		if (e)
			e(NULL);
		else if (ee)
			ee(retval, NULL);
	}

	free(message);
	return retval;
}
