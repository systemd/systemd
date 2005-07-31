/*
 * usb_id.c
 *
 * Identify an USB (block) device
 *
 * Copyright (c) 2005 SUSE Linux Products GmbH, Germany
 * Author:
 *	Hannes Reinecke <hare@suse.de>
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 *  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <../../libsysfs/sysfs/libsysfs.h>
#include "../../udev_utils.h"
#include "../../logging.h"

#define	MAX_NAME_LEN			72
#define	MAX_SERIAL_LEN			256
#define BLKGETSIZE64 _IOR(0x12,114,size_t)

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

char sysfs_mnt_path[SYSFS_PATH_MAX];
static char vendor_str[64];
static char model_str[64];
static char serial_str[MAX_SERIAL_LEN];
static char revision_str[16];
static char type_str[16];

static int use_usb_info;
static int use_num_info;
static int export;
static int debug;

static void set_str(char *to, const char *from, size_t count)
{
	size_t i, j, len;

	/* strip trailing whitespace */
	len = strnlen(from, count);
	while (isspace(from[len-1]))
		len--;

	/* strip leading whitespace */
	i = 0;
	while (isspace(from[i]) && (i < len))
		i++;

	j = 0;
	while (i < len) {
		/* substitute multiple whitespace */
		if (isspace(from[i])) {
			while (isspace(from[i]))
				i++;
			to[j++] = '_';
		}
		/* Replace '/' with '.' */
		if (from[i] == '/') {
			to[j++] = '.';
			i++;
			continue;
		}
		/* skip non-printable chars */
		if (!isalnum(from[i]) && !ispunct(from[i])) {
			i++;
			continue;
		}
		to[j++] = from[i++];
	}
	to[j] = '\0';
}

/*
 * set_usb_iftype
 *
 * Set the type based on the USB interface class
 */
static void set_usb_iftype(char *to, const char *from, int count)
{
	int type_num;
	char *eptr;

	type_num = strtoul(from, &eptr, 0);
	if (eptr != from) {
		switch (type_num) {
		case 1:
			sprintf(to, "audio");
			break;
		case 3:
			sprintf(to, "hid");
			break;
		case 7:
			sprintf(to, "printer");
			break;
		case 8:
			sprintf(to, "disk");
			break;
		case 2: /* CDC-Control */
		case 5: /* Physical */
		case 6: /* Image */
		case 9: /* HUB */
		case 0x0a: /* CDC-Data */
		case 0x0b: /* Chip/Smart Card */
		case 0x0d: /* Content Security */
		case 0x0e: /* Video */
		case 0xdc: /* Diagnostic Device */
		case 0xe0: /* Wireless Controller */
		case 0xf2: /* Application-specific */
		case 0xff: /* Vendor-specific */
		default:
			sprintf(to, "generic");
			break;
		}
	} else {
		sprintf(to, "generic");
	}
}

/*
 * set_usb_ifsybtype
 *
 * Set the type base on the interfaceSubClass.
 * Valid for Mass-Storage devices (type 8) only.
 */
static int set_usb_ifsubtype(char *to, const char *from, int count)
{
	int type_num = 0;
	char *eptr;

	type_num = strtoul(from, &eptr, 0);
	if (eptr != from) {
		switch (type_num) {
		case 2:
			sprintf(to, "cd");
			break;
		case 3:
			sprintf(to, "tape");
			break;
		case 4: /* UFI */
		case 5: /* SFF-8070i */
			sprintf(to, "floppy");
			break;
		case 1: /* RBC devices */
		case 6: /* Transparent SPC-2 devices */
			sprintf(to, "disk");
			break;
		}
	} else {
		sprintf(to, "generic");
	}

	return type_num;
}

static void set_scsi_type(char *to, const char *from, int count)
{
	int type_num;
	char *eptr;

	type_num = strtoul(from, &eptr, 0);
	if (eptr != from) {
		switch (type_num) {
		case 0:
			sprintf(to, "disk");
			break;
		case 1:
			sprintf(to, "tape");
			break;
		case 4:
			sprintf(to, "optical");
			break;
		case 5:
			sprintf(to, "cd");
			break;
		case 7:
			sprintf(to, "optical");
			break;
		case 0xe:
			sprintf(to, "disk");
			break;
		case 0xf:
			sprintf(to, "optical");
			break;
		default:
			sprintf(to, "generic");
			break;
		}
	} else {
		sprintf(to, "generic");
	}
}

/*
 * A unique USB identification is generated like this:
 *
 * 1.) Get the USB device type from DeviceClass, InterfaceClass
 *     and InterfaceSubClass
 * 2.) If the device type is 'Mass-Storage/SPC-2' or 'Mass-Storage/RBC'
 *     use the SCSI vendor and model as USB-Vendor and USB-model.
 * 3.) Otherwise use the USB manufacturer and product as
 *     USB-Vendor and USB-model. Any non-printable characters
 *     in those strings will be skipped; a slash '/' will be converted
 *     into a full stop '.'.
 * 4.) If that fails, too, we will use idVendor and idProduct
 *     as USB-Vendor and USB-model.
 * 5.) The USB identification is the USB-vendor and USB-model
 *     string concatenated with an underscore '_'.
 * 6.) If the device supplies a serial number, this number
 *     is concatenated with the identification with an underscore '_'.
 */
static int usb_id(const char *target_path)
{
	struct sysfs_class_device *class_dev; /* of target_path */
	struct sysfs_class_device *class_dev_parent; /* for partitions */
	struct sysfs_device *scsi_dev; /* the scsi_device */
	struct sysfs_device *target_dev;
	struct sysfs_device *host_dev, *interface_dev, *usb_dev;
	struct sysfs_attribute *scsi_model, *scsi_vendor, *scsi_type, *scsi_rev;
	struct sysfs_attribute *usb_model = NULL, *usb_vendor = NULL, *usb_rev, *usb_serial;
	struct sysfs_attribute *if_class, *if_subclass;
	int if_class_num;
	int protocol = 0;

	class_dev = sysfs_open_class_device_path(target_path);
	if (!class_dev) {
		info("open class %s failed: %s", target_path, strerror(errno));
		return 1;
	}
	class_dev_parent = sysfs_get_classdev_parent(class_dev);
	if (class_dev_parent) {
		scsi_dev = sysfs_get_classdev_device(class_dev_parent);
	} else {
		scsi_dev = sysfs_get_classdev_device(class_dev);
	}

	/*
	 * The close of scsi_dev will close class_dev or class_dev_parent.
	 */

	/*
	 * We assume we are called after the device is completely ready,
	 * so we don't have to loop here like udev. (And we are usually
	 * called via udev.)
	 */
	if (!scsi_dev) {
		/*
		 * errno is not set if we can't find the device link, so
		 * don't print it out here.
		 */
		info("Cannot find sysfs device associated with %s", target_path);
		return 1;
	}

	/*
	 * Allow only scsi devices.
	 *
	 * Other block devices can support SG IO, but only ide-cd does, so
	 * for now, don't bother with anything else.
	 */
	if (strcmp(scsi_dev->bus, "scsi") != 0) {
		info("%s is not a scsi device", target_path);
		return 1;
	}

	/* target directory */
	target_dev = sysfs_get_device_parent(scsi_dev);
	/* host directory */
	host_dev = sysfs_get_device_parent(target_dev);
	/* usb interface directory */
	interface_dev = sysfs_get_device_parent(host_dev);
	/* usb device directory */
	usb_dev = sysfs_get_device_parent(interface_dev);

	if (strcmp(interface_dev->bus, "usb") != 0) {
		info("%s is not an usb device", target_path);
		return 1;
	}

	if_class = sysfs_get_device_attr(interface_dev, "bInterfaceClass");
	if (!if_class) {
		info("%s: cannot get bInterfaceClass attribute", interface_dev->name);
		return 1;
	}
	if_class_num = strtoul(if_class->value, NULL, 16);
	if (if_class_num != 8) {
		set_usb_iftype(type_str, if_class->value, sizeof(type_str) - 1);
		protocol = 0;
	} else {
		if_subclass = sysfs_get_device_attr(interface_dev, 
						    "bInterfaceSubClass");
		protocol = set_usb_ifsubtype(type_str, if_subclass->value, 
					     sizeof(type_str) -1 );
	}

	if (!use_usb_info && protocol == 6) {
		/* Generic SPC-2 device */
		scsi_vendor = sysfs_get_device_attr(scsi_dev, "vendor");
		if (!scsi_vendor) {
			info("%s: cannot get SCSI vendor attribute", scsi_dev->name);
			return 1;
		}
		set_str(vendor_str, scsi_vendor->value, sizeof(vendor_str)-1);

		scsi_model = sysfs_get_device_attr(scsi_dev, "model");
		if (!scsi_model) {
			info("%s: cannot get SCSI model attribute", scsi_dev->name);
			return 1;
		}
		set_str(model_str, scsi_model->value, sizeof(model_str)-1);

		scsi_type = sysfs_get_device_attr(scsi_dev, "type");
		if (!scsi_type) {
			info("%s: cannot get SCSI type attribute", scsi_dev->name);
			return 1;
		}
		set_scsi_type(type_str, scsi_type->value, sizeof(type_str)-1);

		scsi_rev = sysfs_get_device_attr(scsi_dev, "rev");
		if (!scsi_rev) {
			info("%s: cannot get SCSI revision attribute", scsi_dev->name);
			return 1;
		}
		set_str(revision_str, scsi_rev->value, sizeof(revision_str)-1);

	}

	/* Fallback to USB vendor & device */
	if (vendor_str[0] == '\0') {
		if (!use_num_info)
			if (!(usb_vendor = sysfs_get_device_attr(usb_dev, "manufacturer")))
				dbg("No USB vendor string found, using idVendor");

		if (!usb_vendor) {
			if (!(usb_vendor = sysfs_get_device_attr(usb_dev, "idVendor"))) {
				dbg("No USB vendor information available\n");
				sprintf(vendor_str,"0000");
			}
		}
		set_str(vendor_str,usb_vendor->value, sizeof(vendor_str) - 1);
	}
	
	if (model_str[0] == '\0') {
		if (!use_num_info)
			if (!(usb_model = sysfs_get_device_attr(usb_dev, "product")))
				dbg("No USB model string found, using idProduct");
		
		if (!usb_model) {
			if (!(usb_model = sysfs_get_device_attr(usb_dev, "idProduct"))) {
				dbg("No USB model information available\n");
				sprintf(model_str,"0000");
			}
		}
		set_str(model_str, usb_model->value, sizeof(model_str) - 1);
	}

	if (revision_str[0] == '\0') {
		usb_rev = sysfs_get_device_attr(usb_dev, "bcdDevice");
		if (usb_rev) {
			set_str(revision_str, usb_rev->value, 
				sizeof(revision_str) - 1);
		}
	}

	if (serial_str[0] == '\0') {
		usb_serial = sysfs_get_device_attr(usb_dev, "serial");
		if (usb_serial) {
			set_str(serial_str, usb_serial->value,
				sizeof(serial_str) - 1);
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	int retval;
	char *devpath;
	char target_path[MAX_NAME_LEN];
	int option;

	dbg("argc is %d", argc);
	if (sysfs_get_mnt_path(sysfs_mnt_path, MAX_NAME_LEN)) {
		info("sysfs_get_mnt_path failed: %s",
			strerror(errno));
		exit(1);
	}

	while ((option = getopt(argc, argv, "dnux")) != -1 ) {
		if (optarg)
			dbg("option '%c' arg '%s'", option, optarg);
		else
			dbg("option '%c'", option);

		switch (option) {
		case 'd':
			debug = 1;
			break;
		case 'n':
			use_num_info=1;
			use_usb_info=1;
			break;
		case 'u':
			use_usb_info=1;
			break;
		case 'x':
			export=1;
			break;
		default:
			info("Unknown or bad option '%c' (0x%x)", option, option);
			retval = 1;
			break;
		}
	}

	devpath = getenv("DEVPATH");
	if (devpath) {
		strncpy(target_path, sysfs_mnt_path, MAX_NAME_LEN);
		strncat(target_path, devpath, MAX_NAME_LEN);
	} else {
		if (optind == argc) {
			fprintf(stderr, "No device specified\n");
			exit(1);
		}
		devpath = argv[optind];
		strncpy(target_path, devpath, MAX_NAME_LEN);
	}

	retval = usb_id(target_path);

	if (retval == 0) {
		if (export) {
			printf("ID_VENDOR=%s\n", vendor_str);
			printf("ID_MODEL=%s\n", model_str);
			printf("ID_REVISION=%s\n", revision_str);
			if (serial_str[0] == '\0') {
				printf("ID_SERIAL=%s_%s\n", 
				       vendor_str, model_str);
			} else {
				printf("ID_SERIAL=%s_%s_%s\n", 
				       vendor_str, model_str, serial_str);
			}
			printf("ID_TYPE=%s\n", type_str);
			printf("ID_BUS=usb\n");
		} else {
			if (serial_str[0] == '\0') {
				printf("%s_%s\n", 
				       vendor_str, model_str);
			} else {
				printf("%s_%s_%s\n", 
				       vendor_str, model_str, serial_str);
			}
		}
	}
	exit(retval);
}
