/*
 * A simple firmware helper program.
 * 
 * Copyright 2005 Red Hat, Inc.
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../udev_utils.h"
#include "../../logging.h"

#define FIRMWARE_PATH			"/lib/firmware"
#define PATH_SIZE			256

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;
	static int udev_log = -1;

	if (udev_log == -1) {
		const char *value;

		value = getenv("UDEV_LOG");
		if (value)
			udev_log = log_priority(value);
		else
			udev_log = LOG_ERR;
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

/* Set the 'loading' attribute for a firmware device.
 * 1 == currently loading
 * 0 == done loading
 * -1 == error
 */
static int set_loading(const char *device, int value) {
	char loading_path[PATH_SIZE];
	int rc;
	FILE *f;

	snprintf(loading_path, sizeof(loading_path), "/sys/%s/loading", device);
	loading_path[sizeof(loading_path)-1] = '\0';
	f = fopen(loading_path, "w");
	if (!f)
		return -1;
	rc = fprintf(f, "%d", value);
	fclose(f);
	if (rc < 0)
		return rc;
	return 0;
}

int main(int argc, char **argv) {
	char *devpath, *firmware, *action, *driver;
	char fw_path[PATH_SIZE];
	char data_path[PATH_SIZE];
	int fw_fd;
	char *fw_buffer;
	size_t fw_buffer_size;
	size_t count;
	int rc = 0;

	logging_init("firmware_helper");

	driver = getenv("PHYSDEVDRIVER");
	if (!driver)
		driver = "(unknown)";
	devpath = getenv("DEVPATH");
	firmware = getenv("FIRMWARE");
	action = getenv("ACTION");
	if (!devpath || !firmware || !action || strcmp(action,"add") != 0) {
		err("missing devpath, action or firmware");
		exit(1);
	}

	dbg("try to load firmware '%s' for '%s'", firmware, devpath);
	set_loading(devpath, 1);

	snprintf(fw_path, sizeof(fw_path), "%s/%s", FIRMWARE_PATH, firmware);
	fw_path[sizeof(fw_path)-1] = '\0';
	if (file_map(fw_path, &fw_buffer, &fw_buffer_size) != 0 || fw_buffer_size == 0) {
		err("could not load firmware '%s' for '%s'", fw_path, devpath);
		fw_buffer = NULL;
		goto out_err;
	}

	snprintf(data_path, sizeof(data_path), "/sys/%s/data", devpath);
	data_path[sizeof(data_path)-1] = '\0';
	fw_fd = open(data_path, O_RDWR);
	if (fw_fd < 0) {
		rc = errno;
		goto out_err;
	}

	count = 0;
	while (count < fw_buffer_size) {
		ssize_t c;

		c = write(fw_fd, fw_buffer+count, fw_buffer_size-count);
		if (c <= 0) {
			rc = errno;
			close(fw_fd);
			goto out_err;
		}
		count += c;
	}

	close(fw_fd);
	file_unmap(fw_buffer, fw_buffer_size);
	set_loading(devpath, 0);
	info("loaded '%s' for device '%s'", fw_path, devpath);
	logging_close();
	return 0;

out_err:
	if (fw_buffer)
		file_unmap(fw_buffer, fw_buffer_size);
	set_loading(devpath, -1);

	err("error loading '%s' for device '%s' with driver '%s'", fw_path, devpath, driver);
	logging_close();
	return rc;
}
