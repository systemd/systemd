/*
 * udevrulescompile.c - store already parsed config on disk
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
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
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "udev_libc_wrapper.h"
#include "udev_sysfs.h"
#include "udev.h"
#include "udev_version.h"
#include "logging.h"
#include "udev_rules.h"
#include "udev_utils.h"
#include "list.h"

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;

	if (priority > udev_log_priority)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	struct udev_rules rules;
	FILE *f;
	char comp[PATH_SIZE];
	char comp_tmp[PATH_SIZE];
	int retval = 0;

	logging_init("udevrulescompile");
	udev_init_config();
	dbg("version %s", UDEV_VERSION);

	strlcpy(comp, udev_rules_filename, sizeof(comp));
	strlcat(comp, ".compiled", sizeof(comp));
	strlcpy(comp_tmp, comp, sizeof(comp_tmp));
	strlcat(comp_tmp, ".tmp", sizeof(comp_tmp));

	/* remove old version, otherwise we would read it instead of the real rules */
	unlink(comp);
	unlink(comp_tmp);

	udev_rules_init(&rules, 1);

	f = fopen(comp_tmp, "w");
	if (f == NULL) {
		err("unable to create db file '%s'", comp_tmp);
		unlink(comp_tmp);
		retval = 1;
		goto exit;
	}

	dbg("storing compiled rules in '%s' size=%zi", comp_tmp, rules.bufsize);
	fwrite(rules.buf, rules.bufsize, 1, f);
	fclose(f);

	dbg("activating compiled rules in '%s'", comp);
	if (rename(comp_tmp, comp) != 0) {
		err("unable to write file");
		unlink(comp);
		unlink(comp_tmp);
		retval = 2;
	}

exit:
	logging_close();
	return retval;
}
