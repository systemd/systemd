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
	char *service;
	char *exec;
	int idx = 0;
	RC_SERVICE state, bit;

	applet = basename_c(argv[0]);
	if (argc > 1)
		service = argv[1];
	else
		service = getenv("RC_SVCNAME");

	if (service == NULL || *service == '\0')
		eerrorx("%s: no service specified", applet);

	state = rc_service_state(service);
	bit = lookup_service_state(applet);
	if (bit) {
		ok = (state & bit);
	} else if (strcmp(applet, "service_started_daemon") == 0) {
		service = getenv("RC_SVCNAME");
		exec = argv[1];
		if (argc > 3) {
			service = argv[1];
			exec = argv[2];
			sscanf(argv[3], "%d", &idx);
		} else if (argc == 3) {
			if (sscanf(argv[2], "%d", &idx) != 1) {
				service = argv[1];
				exec = argv[2];
			}
		}
		ok = rc_service_started_daemon(service, exec, NULL, idx);

	} else if (strcmp(applet, "service_crashed") == 0) {
		ok = (_rc_can_find_pids() &&
		    rc_service_daemons_crashed(service) &&
		    errno != EACCES);
	} else
		eerrorx("%s: unknown applet", applet);

	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
