/*
 * compose persistent device path
 *
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * Logic based on Hannes Reinecke's shell script.
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

#include "libudev.h"
#include "libudev-private.h"

static int debug;

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

static struct udev_device *handle_scsi_fibre_channel(struct udev_device *parent, char **path)
{
	struct udev *udev  = udev_device_get_udev(parent);
	struct udev_device *targetdev;
	struct udev_device *fcdev = NULL;
	const char *port;
	unsigned int lun;

	targetdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_target");
	if (targetdev == NULL)
		return NULL;

	fcdev = udev_device_new_from_subsystem_sysname(udev, "fc_transport", udev_device_get_sysname(targetdev));
	if (fcdev == NULL)
		return NULL;
	port = udev_device_get_sysattr_value(fcdev, "port_name");
	if (port == NULL) {
		parent = NULL;
		goto out;
	}

	lun = strtoul(udev_device_get_sysnum(parent), NULL, 10);
	path_prepend(path, "fc-%s:0x%04x%04x00000000", port, lun & 0xffff, (lun >> 16) & 0xffff);
out:
	udev_device_unref(fcdev);
	return parent;
}

static struct udev_device *handle_scsi_sas(struct udev_device *parent, char **path)
{
	return NULL;
}

static struct udev_device *handle_scsi_iscsi(struct udev_device *parent, char **path)
{
	struct udev *udev  = udev_device_get_udev(parent);
	struct udev_device *transportdev;
	struct udev_device *sessiondev = NULL;
	const char *target;
	char *connname;
	struct udev_device *conndev = NULL;
	const char *addr;
	const char *port;

	/* find iscsi session */
	transportdev = parent;
	while (1) {
		transportdev = udev_device_get_parent(transportdev);
		if (transportdev == NULL)
			return NULL;
		if (strncmp(udev_device_get_sysname(transportdev), "session", 7) == 0)
			break;
	}
	if (transportdev == NULL)
		return NULL;

	/* find iscsi session device */
	sessiondev = udev_device_new_from_subsystem_sysname(udev, "iscsi_session", udev_device_get_sysname(transportdev));
	if (sessiondev == NULL)
		return NULL;
	target = udev_device_get_sysattr_value(sessiondev, "targetname");
	if (target == NULL) {
		parent = NULL;
		goto out;
	}

	if (asprintf(&connname, "connection%s:0", udev_device_get_sysnum(transportdev)) < 0) {
		parent = NULL;
		goto out;
	}
	conndev = udev_device_new_from_subsystem_sysname(udev, "iscsi_connection", connname);
	free(connname);
	if (conndev == NULL) {
		parent = NULL;
		goto out;
	}
	addr = udev_device_get_sysattr_value(conndev, "persistent_address");
	port = udev_device_get_sysattr_value(conndev, "persistent_port");
	if (addr == NULL || port == NULL) {
		parent = NULL;
		goto out;
	}

	path_prepend(path, "ip-%s:%s-iscsi-%s-lun-%s", addr, port, target, udev_device_get_sysnum(parent));
out:
	udev_device_unref(sessiondev);
	udev_device_unref(conndev);
	return parent;
}

static struct udev_device *handle_scsi_default(struct udev_device *parent, char **path)
{
	struct udev_device *hostdev;
	int host, bus, target, lun;
	const char *name;
	char *base;
	char *pos;
	DIR *dir;
	struct dirent *dent;
	int basenum;

	hostdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host");
	if (hostdev == NULL)
		return NULL;

	name = udev_device_get_sysname(parent);
	if (sscanf(name, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4)
		return NULL;

	/* rebase host offset to get the local relative number */
	basenum = -1;
	base = strdup(udev_device_get_syspath(hostdev));
	if (base == NULL)
		return NULL;
	pos = strrchr(base, '/');
	if (pos == NULL) {
		parent = NULL;
		goto out;
	}
	pos[0] = '\0';
	dir = opendir(base);
	if (dir == NULL) {
		parent = NULL;
		goto out;
	}
	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		char *rest;
		int i;

		if (dent->d_name[0] == '.')
			continue;
		if (dent->d_type != DT_DIR && dent->d_type != DT_LNK)
			continue;
		if (strncmp(dent->d_name, "host", 4) != 0)
			continue;
		i = strtoul(&dent->d_name[4], &rest, 10);
		if (rest[0] != '\0')
			continue;
		if (basenum == -1 || i < basenum)
			basenum = i;
	}
	closedir(dir);
	if (basenum == -1) {
		parent = NULL;
		goto out;
	}
	host -= basenum;

	path_prepend(path, "scsi-%u:%u:%u:%u", host, bus, target, lun);
out:
	free(base);
	return hostdev;
}

static struct udev_device *handle_scsi(struct udev_device *parent, char **path)
{
	const char *devtype;
	const char *name;
	const char *id;

	devtype = udev_device_get_devtype(parent);
	if (devtype == NULL || strcmp(devtype, "scsi_device") != 0)
		return parent;

	/* firewire */
	id = udev_device_get_sysattr_value(parent, "ieee1394_id");
	if (id != NULL) {
		parent = skip_subsystem(parent, "scsi");
		path_prepend(path, "ieee1394-0x%s", id);
		goto out;
	}

	/* lousy scsi sysfs does not have a "subsystem" for the transport */
	name = udev_device_get_syspath(parent);

	if (strstr(name, "/rport-") != NULL) {
		parent = handle_scsi_fibre_channel(parent, path);
		goto out;
	}

	if (strstr(name, "/end_device-") != NULL) {
		parent = handle_scsi_sas(parent, path);
		goto out;
	}

	if (strstr(name, "/session") != NULL) {
		parent = handle_scsi_iscsi(parent, path);
		goto out;
	}

	parent = handle_scsi_default(parent, path);
out:
	return parent;
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

static struct udev_device *handle_usb(struct udev_device *parent, char **path)
{
	const char *devtype;
	const char *str;
	const char *port;

	devtype = udev_device_get_devtype(parent);
	if (devtype == NULL || strcmp(devtype, "usb_interface") != 0)
		return parent;

	str = udev_device_get_sysname(parent);
	port = strchr(str, '-');
	if (port == NULL)
		return parent;
	port++;

	parent = skip_subsystem(parent, "usb");
	path_prepend(path, "usb-0:%s", port);
	return parent;
}

static struct udev_device *handle_cciss(struct udev_device *parent, char **path)
{
	return NULL;
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

	udev_log_init("path_id");
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

	/* S390 ccw bus */
	parent = udev_device_get_parent_with_subsystem_devtype(dev, "ccw", NULL);
	if (parent != NULL) {
		handle_ccw(parent, dev, &path);
		goto out;
	}

	/* walk up the chain of devices and compose path */
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
		} else if (strcmp(subsys, "cciss") == 0) {
			handle_cciss(parent, &path);
		} else if (strcmp(subsys, "usb") == 0) {
			parent = handle_usb(parent, &path);
		} else if (strcmp(subsys, "serio") == 0) {
			path_prepend(&path, "serio-%s", udev_device_get_sysnum(parent));
			parent = skip_subsystem(parent, "serio");
		} else if (strcmp(subsys, "pci") == 0) {
			path_prepend(&path, "pci-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "pci");
		} else if (strcmp(subsys, "platform") == 0) {
			path_prepend(&path, "platform-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "platform");
		} else if (strcmp(subsys, "xen") == 0) {
			path_prepend(&path, "xen-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "xen");
		} else if (strcmp(subsys, "virtio") == 0) {
			path_prepend(&path, "virtio-pci-%s", udev_device_get_sysname(parent));
			parent = skip_subsystem(parent, "virtio");
		}

		parent = udev_device_get_parent(parent);
	}
out:
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
	udev_log_close();
	return rc;
}
