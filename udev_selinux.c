#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <selinux/selinux.h>

#include "udev.h"
#include "udev_lib.h"
#include "logging.h"

#ifdef LOG
unsigned char logname[LOGNAME_SIZE];
void log_message(int level, const char *format, ...)
{
	va_list args;

	if (!udev_log)
		return;

	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
}
#endif

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

int main(int argc, char *argv[], char *envp[])
{
	char *action;
	char *devpath;
	char *devnode;
	int retval = 0;

	init_logging("udev_selinux");

	action = get_action();
	if (!action) {
		dbg("no action?");
		goto exit;
	}
	devnode = get_devnode();
	if (!devnode) {
		dbg("no devnode?");
		goto exit;
	}

	if (strcmp(action, "add") == 0)
		selinux_add_node(devnode);

exit:
	return retval;
}
