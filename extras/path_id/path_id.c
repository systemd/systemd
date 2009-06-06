/*
 * compose persisistent device path
 *
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>

#include <libudev.h>
#include <../../udev/udev.h>

int debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "%s: ", fn != NULL ? fn : file);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

static int path_prepend(char **path, const char *fmt, ...)
{
	va_list va;
	char *old;
	char *pre;
	int err;

	old = *path;

	va_start(va, fmt);
	err = vasprintf(&pre, fmt, va);
	va_end(va);
	if (err < 0)
		return err;

	if (old != NULL) {
		err = asprintf(path, "%s-%s", pre, old);
		if (err < 0)
			return err;
		free(pre);
	} else {
		*path = pre;
	}

	free(old);
	return 0;
}

static struct udev_device *skip_subsystem(struct udev_device *dev, const char *subsys)
{
	struct udev_device *parent = dev;

	while (parent != NULL) {
		const char *subsystem;

		subsystem = udev_device_get_subsystem(parent);
		if (subsystem == NULL || strcmp(subsystem, subsys) != 0)
			break;
		dev = parent;
		parent = udev_device_get_parent(parent);
	}
	return dev;
}

/* find smallest number of instances of <syspath>/<name><number> */
static int base_number(const char *syspath, const char *name)
{
	char *base;
	char *pos;
	DIR *dir;
	struct dirent *dent;
	size_t len;
	int number = -1;

	base = strdup(syspath);
	if (base == NULL)
		goto out;

	pos = strrchr(base, '/');
	if (pos == NULL)
		goto out;
	pos[0] = '\0';

	len = strlen(name);
	dir = opendir(base);
	if (dir == NULL)
		goto out;
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char *rest;
		int i;

		if (dent->d_name[0] == '.')
			continue;
		if (dent->d_type != DT_DIR && dent->d_type != DT_LNK)
			continue;
		if (strncmp(dent->d_name, name, len) != 0)
			continue;
		i = strtoul(&dent->d_name[len], &rest, 10);
		if (rest[0] != '\0')
			continue;
		if (number == -1 || i < number)
			number = i;
	}
	closedir(dir);
out:
	free(base);
	return number;
}

static struct udev_device *handle_scsi(struct udev_device *dev, char **path)
{
	const char *devtype;
	struct udev_device *hostdev;
	const char *name;
	int host, bus, target, lun;
	int base;

	devtype = udev_device_get_devtype(dev);
	if (devtype == NULL || strcmp(devtype, "scsi_device") != 0)
		return dev;

	hostdev = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_host");
	if (hostdev == NULL)
		return dev;

	name = udev_device_get_sysname(dev);
	if (sscanf(name, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4)
		return dev;

	/* rebase host offset to get the local relative number */
	base = base_number(udev_device_get_syspath(hostdev), "host");
	if (base < 0)
		return dev;
	host -= base;

	path_prepend(path, "scsi-%u:%u:%u:%u", host, bus, target, lun);
	dev = skip_subsystem(dev, "scsi");
	return dev;
}

static void handle_scsi_tape(struct udev_device *dev, char **suffix)
{
	const char *name;

	name = udev_device_get_sysname(dev);
	if (strncmp(name, "nst", 3) == 0 && strchr("lma", name[3]) != NULL)
		asprintf(suffix, "nst%c", name[3]);
	else if (strncmp(name, "st", 2) == 0 && strchr("lma", name[2]) != NULL)
		asprintf(suffix, "st%c", name[2]);
}

static struct udev_device *handle_usb(struct udev_device *dev, char **path)
{
	const char *devtype;
	const char *str;
	const char *port;

	devtype = udev_device_get_devtype(dev);
	if (devtype == NULL || strcmp(devtype, "usb_interface") != 0)
		return dev;

	str = udev_device_get_sysname(dev);
	port = strchr(str, '-');
	if (port == NULL)
		return dev;
	port++;

	dev = skip_subsystem(dev, "usb");
	path_prepend(path, "usb-0:%s", port);
	return dev;
}

static struct udev_device *handle_firewire(struct udev_device *parent, struct udev_device *dev, char **path)
{
	struct udev_device *scsi_dev;

	scsi_dev = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_device");
	if (scsi_dev != NULL) {
		const char *id;

		id = udev_device_get_sysattr_value(scsi_dev, "ieee1394_id");
		if (id != NULL)
			path_prepend(path, "ieee1394-0x%s", id);
	}

	parent = skip_subsystem(parent, "firewire");
	return parent;
}

static struct udev_device *handle_ccw(struct udev_device *parent, struct udev_device *dev, char **path)
{
	struct udev_device *scsi_dev;

	scsi_dev = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_device");
	if (scsi_dev != NULL) {
		const char *wwpn;
		const char *lun;
		const char *hba_id;

		hba_id = udev_device_get_sysattr_value(scsi_dev, "hba_id");
		wwpn = udev_device_get_sysattr_value(scsi_dev, "wwpn");
		lun = udev_device_get_sysattr_value(scsi_dev, "fcp_lun");
		if (hba_id != NULL && lun != NULL && wwpn != NULL) {
			path_prepend(path, "ccw-%s-zfcp-%s:%s", hba_id, wwpn, lun);
			goto out;
		}
	}

	path_prepend(path, "ccw-%s", udev_device_get_sysname(parent));
out:
	parent = skip_subsystem(parent, "ccw");
	return parent;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	struct udev *udev;
	struct udev_device *dev;
	struct udev_device *parent;
	char syspath[UTIL_PATH_SIZE];
	const char *devpath;
	char *path;
	char *path_suffix;
	int rc = 1;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	logging_init("usb_id");
	udev_set_log_fn(udev, log_fn);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'h':
			printf("Usage: path_id [--debug] [--help] <devpath>\n"
			       "  --debug    print debug information\n"
			       "  --help      print this help text\n\n");
		default:
			rc = 1;
			goto exit;
		}
	}

	devpath = argv[optind];
	if (devpath == NULL) {
		fprintf(stderr, "No device specified\n");
		rc = 2;
		goto exit;
	}

	util_strscpyl(syspath, sizeof(syspath), udev_get_sys_path(udev), devpath, NULL);
	dev = udev_device_new_from_syspath(udev, syspath);
	if (dev == NULL) {
		fprintf(stderr, "unable to access '%s'\n", devpath);
		rc = 3;
		goto exit;
	}

	path = NULL;
	path_suffix = NULL;

	parent = dev;
	while (parent != NULL) {
		const char *subsys;

		subsys = udev_device_get_subsystem(parent);

		if (subsys == NULL) {
			;
		} else if (strcmp(subsys, "scsi_tape") == 0) {
			handle_scsi_tape(parent, &path_suffix);
		} else if (strcmp(subsys, "scsi") == 0) {
			parent = handle_scsi(parent, &path);
		} else if (strcmp(subsys, "fc_transport") == 0) {
			; //handle_fc();
		} else if (strcmp(subsys, "sas_end_device") == 0) {
			; //handle_sas();
		} else if (strcmp(subsys, "iscsi_session") == 0) {
			; //handle_iscsi()
		} else if (strcmp(subsys, "ccw") == 0) {
			handle_ccw(parent, dev, &path);
		} else if (strcmp(subsys, "cciss") == 0) {
			; //handle_cciss();
		} else if (strcmp(subsys, "usb") == 0) {
			parent = handle_usb(parent, &path);
		} else if (strcmp(subsys, "serio") == 0) {
			path_prepend(&path, "serio-%s", udev_device_get_sysnum(parent));
			parent = skip_subsystem(parent, "serio");
		} else if (strcmp(subsys, "firewire") == 0 || strcmp(subsys, "ieee1394") == 0) {
			parent = handle_firewire(parent, dev, &path);
		} else if (strcmp(subsys, "pci") == 0) {
			path_prepend(&path, "pci-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "pci");
		} else if (strcmp(subsys, "platform") == 0) {
			path_prepend(&path, "platform-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "platform");
		} else if (strcmp(subsys, "xen") == 0) {
			path_prepend(&path, "xen-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "xen");
		}

		parent = udev_device_get_parent(parent);
	}

	if (path != NULL) {
		if (path_suffix != NULL) {
			printf("ID_PATH=%s%s\n", path, path_suffix);
			free(path_suffix);
		} else {
			printf("ID_PATH=%s\n", path);
		}
		free(path);
		rc = 0;
	}

	udev_device_unref(dev);
exit:
	udev_unref(udev);
	logging_close();
	return rc;
}
