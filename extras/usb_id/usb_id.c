/*
 * usb_id.c
 *
 * Identify an USB (block) device
 *
 * Copyright (c) 2005 SUSE Linux Products GmbH, Germany
 *
 * Author:
 *	Hannes Reinecke <hare@suse.de>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "../../udev.h"

#define MAX_PATH_LEN			512
#define MAX_SERIAL_LEN			256
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

static char vendor_str[64];
static char model_str[64];
static char serial_str[MAX_SERIAL_LEN];
static char revision_str[16];
static char type_str[16];

static int use_usb_info;
static int use_num_info;
static int export;

static void set_str(char *to, const char *from, size_t count)
{
	size_t i, j, len;

	/* strip trailing whitespace */
	len = strnlen(from, count);
	while (len && isspace(from[len-1]))
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

static void set_usb_iftype(char *to, int if_class_num, size_t len)
{
	char *type = "generic";

	switch (if_class_num) {
	case 1:
		type = "audio";
		break;
	case 3:
		type = "hid";
		break;
	case 7:
		type = "printer";
		break;
	case 8:
		type = "disk";
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
		break;
	default:
		break;
	}
	strncpy(to, type, len);
	to[len-1] = '\0';
}

static int set_usb_mass_storage_ifsubtype(char *to, const char *from, size_t len)
{
	int type_num = 0;
	char *eptr;
	char *type = "generic";

	type_num = strtoul(from, &eptr, 0);
	if (eptr != from) {
		switch (type_num) {
		case 2:
			type = "cd";
			break;
		case 3:
			type = "tape";
			break;
		case 4: /* UFI */
		case 5: /* SFF-8070i */
			type = "floppy";
			break;
		case 1: /* RBC devices */
		case 6: /* Transparent SPC-2 devices */
			type = "disk";
			break;
		default:
			break;
		}
	}
	strncpy(to, type, len);
	to[len-1] = '\0';

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
static int usb_id(const char *devpath)
{
	struct sysfs_device *dev;
	struct sysfs_device *dev_interface;
	struct sysfs_device *dev_usb;
	const char *scsi_model, *scsi_vendor, *scsi_type, *scsi_rev;
	const char *usb_model = NULL, *usb_vendor = NULL, *usb_rev, *usb_serial;
	const char *if_class, *if_subclass;
	int if_class_num;
	int protocol = 0;

	dbg("devpath %s\n", devpath);

	/* get all usb specific information: dev_interface, if_class, dev_usb */
	dev = sysfs_device_get(devpath);
	if (dev == NULL) {
		err("unable to access '%s'", devpath);
		return 1;
	}

	/* usb interface directory */
	dev_interface = sysfs_device_get_parent_with_subsystem(dev, "usb");
	if (dev_interface == NULL) {
		info("unable to access usb_interface device of '%s'", devpath);
		return 1;
	}

	if_class = sysfs_attr_get_value(dev_interface->devpath, "bInterfaceClass");
	if (!if_class) {
		info("%s: cannot get bInterfaceClass attribute", dev_interface->kernel);
		return 1;
	}
	if_class_num = strtoul(if_class, NULL, 16);
	if (if_class_num == 8) {
		if_subclass = sysfs_attr_get_value(dev_interface->devpath, "bInterfaceSubClass");
		if (if_subclass != NULL)
			protocol = set_usb_mass_storage_ifsubtype(type_str, if_subclass, sizeof(type_str)-1);
	} else
		set_usb_iftype(type_str, if_class_num, sizeof(type_str)-1);

	info("%s: if_class %d protocol %d\n", dev_interface->devpath, if_class_num, protocol);

	/* usb device directory */
	dev_usb = sysfs_device_get_parent_with_subsystem(dev_interface, "usb");
	if (!dev_usb) {
		info("unable to find parent 'usb' device of '%s'", devpath);
		return 1;
	}

	/* mass storage */
	if (protocol == 6 && !use_usb_info) {
		struct sysfs_device *dev_scsi;

		/* get scsi device */
		dev_scsi = sysfs_device_get_parent_with_subsystem(dev, "scsi");
		if (dev_scsi == NULL) {
			info("unable to find parent 'scsi' device of '%s'", devpath);
			goto fallback;
		}

		/* Generic SPC-2 device */
		scsi_vendor = sysfs_attr_get_value(dev_scsi->devpath, "vendor");
		if (!scsi_vendor) {
			info("%s: cannot get SCSI vendor attribute", dev_scsi->kernel);
			goto fallback;
		}
		set_str(vendor_str, scsi_vendor, sizeof(vendor_str)-1);

		scsi_model = sysfs_attr_get_value(dev_scsi->devpath, "model");
		if (!scsi_model) {
			info("%s: cannot get SCSI model attribute", dev_scsi->kernel);
			goto fallback;
		}
		set_str(model_str, scsi_model, sizeof(model_str)-1);

		scsi_type = sysfs_attr_get_value(dev_scsi->devpath, "type");
		if (!scsi_type) {
			info("%s: cannot get SCSI type attribute", dev_scsi->kernel);
			goto fallback;
		}
		set_scsi_type(type_str, scsi_type, sizeof(type_str)-1);

		scsi_rev = sysfs_attr_get_value(dev_scsi->devpath, "rev");
		if (!scsi_rev) {
			info("%s: cannot get SCSI revision attribute", dev_scsi->kernel);
			goto fallback;
		}
		set_str(revision_str, scsi_rev, sizeof(revision_str)-1);
	}

fallback:
	/* Fallback to USB vendor & device */
	if (vendor_str[0] == '\0') {
		if (!use_num_info)
			if (!(usb_vendor = sysfs_attr_get_value(dev_usb->devpath, "manufacturer")))
				dbg("No USB vendor string found, using idVendor");

		if (!usb_vendor) {
			if (!(usb_vendor = sysfs_attr_get_value(dev_usb->devpath, "idVendor"))) {
				dbg("No USB vendor information available\n");
				sprintf(vendor_str,"0000");
			}
		}
		set_str(vendor_str,usb_vendor, sizeof(vendor_str) - 1);
	}
	
	if (model_str[0] == '\0') {
		if (!use_num_info)
			if (!(usb_model = sysfs_attr_get_value(dev_usb->devpath, "product")))
				dbg("No USB model string found, using idProduct");
		
		if (!usb_model) {
			if (!(usb_model = sysfs_attr_get_value(dev_usb->devpath, "idProduct")))
				dbg("No USB model information available\n"); sprintf(model_str,"0000");
		}
		set_str(model_str, usb_model, sizeof(model_str) - 1);
	}

	if (revision_str[0] == '\0') {
		usb_rev = sysfs_attr_get_value(dev_usb->devpath, "bcdDevice");
		if (usb_rev)
			set_str(revision_str, usb_rev, sizeof(revision_str)-1);
	}

	if (serial_str[0] == '\0') {
		usb_serial = sysfs_attr_get_value(dev_usb->devpath, "serial");
		if (usb_serial)
			set_str(serial_str, usb_serial, sizeof(serial_str)-1);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int retval = 0;
	const char *env;
	char devpath[MAX_PATH_LEN];
	int option;

	logging_init("usb_id");
	sysfs_init();

	dbg("argc is %d", argc);

	while ((option = getopt(argc, argv, "dnux")) != -1 ) {
		if (optarg)
			dbg("option '%c' arg '%s'", option, optarg);
		else
			dbg("option '%c'", option);

		switch (option) {
		case 'n':
			use_num_info = 1;
			use_usb_info = 1;
			break;
		case 'u':
			use_usb_info = 1;
			break;
		case 'x':
			export = 1;
			break;
		default:
			info("Unknown or bad option '%c' (0x%x)", option, option);
			retval = 1;
			break;
		}
	}

	env = getenv("DEVPATH");
	if (env != NULL)
		strlcpy(devpath, env, sizeof(devpath));
	else {
		if (optind == argc) {
			fprintf(stderr, "No device specified\n");
			retval = 1;
			goto exit;
		}
		strlcpy(devpath, argv[optind], sizeof(devpath));
	}

	retval = usb_id(devpath);

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

exit:
	sysfs_cleanup();
	logging_close();
	return retval;
}
