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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "rc.h"
#include "rc-misc.h"
#include "_usage.h"
#include "version.h"

#if lint
#  define _noreturn
#endif
#if __GNUC__ > 2 || defined(__INTEL_COMPILER)
#  define _noreturn __attribute__ ((__noreturn__))
#else
#  define _noreturn
#endif

void set_quiet_options(void)
{
	static int qcount = 0;

	qcount ++;
	switch (qcount) {
	case 1:
		setenv ("EINFO_QUIET", "YES", 1);
		break;
	case 2:
		setenv ("EERROR_QUIET", "YES", 1);
		break;
	}
}

_noreturn void show_version(void)
{
	const char *systype = NULL;

	printf("%s (OpenRC", applet);
	if ((systype = rc_sys()))
		printf(" [%s]", systype);
	printf(") %s", VERSION);
#ifdef BRANDING
	printf(" (%s)", BRANDING);
#endif
	printf("\n");
	exit(EXIT_SUCCESS);
}

_noreturn void usage(int exit_status)
{
	const char * const has_arg[] = { "", "<arg>", "[arg]" };
	int i;
	int len;
	char *lo;
	char *p;
	char *token;
	char val[4] = "-?,";

	if (usagestring)
		printf("%s", usagestring);
	else
		printf("Usage: %s [options] ", applet);

	if (extraopts)
		printf("%s", extraopts);

	printf("\n\nOptions: [ %s ]\n", getoptstring);
	for (i = 0; longopts[i].name; ++i) {
		val[1] = longopts[i].val;
		len = printf("  %3s --%s %s", isprint(longopts[i].val) ? val : "",
		    longopts[i].name, has_arg[longopts[i].has_arg]);

		lo = p = xstrdup(longopts_help[i]);
		while ((token = strsep(&p, "\n"))) {
			len = 36 - len;
			if (len > 0)
				printf("%*s", len, "");
			puts(token);
			len = 0;
		}
		free(lo);
	}
	exit(exit_status);
}
