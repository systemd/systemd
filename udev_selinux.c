#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <selinux/selinux.h>

#include "udev.h"
#include "udev_version.h"
#include "udev_selinux.h"
#include "logging.h"


void selinux_add_node(char *filename)
{
	int retval;

	if (is_selinux_enabled() > 0) {
		security_context_t scontext;
		retval = matchpathcon(filename, 0, &scontext);
		if (retval < 0) {
			dbg("matchpathcon(%s) failed\n", filename);
		} else {
			retval=setfilecon(filename,scontext);
			if (retval < 0)
				dbg("setfiles %s failed with error '%s'",
				    filename, strerror(errno));
			free(scontext);
		}
	}
}

