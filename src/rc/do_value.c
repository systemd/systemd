/*
 * Copyright (c) 2016 The OpenRC Authors.
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
#include "rc.h"
#include "rc-misc.h"

const char *applet = NULL;

int main(int argc, char **argv)
{
	bool ok = false;
	char *service = getenv("RC_SVCNAME");
	char *option;

	applet = basename_c(argv[0]);
	if (service == NULL)
		eerrorx("%s: no service specified", applet);

	if (argc < 2 || ! argv[1] || *argv[1] == '\0')
		eerrorx("%s: no option specified", applet);

	if (strcmp(applet, "service_get_value") == 0 ||
	    strcmp(applet, "get_options") == 0)
	{
		option = rc_service_value_get(service, argv[1]);
		if (option) {
			printf("%s", option);
			free(option);
			ok = true;
		}
	} else if (strcmp(applet, "service_set_value") == 0 ||
	    strcmp(applet, "save_options") == 0)
		ok = rc_service_value_set(service, argv[1], argv[2]);
	else
		eerrorx("%s: unknown applet", applet);

	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
