/*
 * usb_id - identify an USB device
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
#include <getopt.h>

#include "../../udev/udev.h"

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

static char vendor_str[64];
static char model_str[64];
static char serial_str[UTIL_NAME_SIZE];
static char revision_str[64];
static char type_str[64];
static char instance_str[64];

static int use_usb_info;
static int use_num_info;

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
		type = "storage";
		break;
	case 2: /* CDC-Control */
	case 5: /* Physical */
	case 6: /* Image */
	case 9: /* HUB */
	case 0x0a: /* CDC-Data */
	case 0x0b: /* Chip/Smart Card */
	case 0x0d: /* Content Security */
	case 0x0e:
		type = "video";
		break;
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
			type = "rbc";
			break;
		case 6: /* Transparent SPC-2 devices */
			type = "scsi";
			break;
		default:
			break;
		}
	}
	util_strlcpy(to, type, len);

	return type_num;
}

static void set_scsi_type(char *to, const char *from, size_t len)
{
	int type_num;
	char *eptr;
	char *type = "generic";

	type_num = strtoul(from, &eptr, 0);
	if (eptr != from) {
		switch (type_num) {
		case 0:
		case 0xe:
			type = "disk";
			break;
		case 1:
			type = "tape";
			break;
		case 4:
		case 7:
		case 0xf:
			type = "optical";
			break;
		case 5:
			type = "cd";
			break;
		default:
			break;
		}
	}
	util_strlcpy(to, type, len);
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
static int usb_id(struct udev_device *dev)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_device *dev_interface;
	struct udev_device *dev_usb;
	const char *if_class, *if_subclass;
	int if_class_num;
	int protocol = 0;

	dbg(udev, "syspath %s\n", udev_device_get_syspath(dev));

	/* usb interface directory */
	dev_interface = udev_device_get_parent_with_subsystem(dev, "usb");
	if (dev_interface == NULL) {
		info(udev, "unable to access usb_interface device of '%s'\n",
		     udev_device_get_syspath(dev));
		return 1;
	}

	if_class = udev_device_get_sysattr_value(dev_interface, "bInterfaceClass");
	if (!if_class) {
		info(udev, "%s: cannot get bInterfaceClass attribute\n",
		     udev_device_get_sysname(dev));
		return 1;
	}
	if_class_num = strtoul(if_class, NULL, 16);
	if (if_class_num == 8) {
		if_subclass = udev_device_get_sysattr_value(dev_interface, "bInterfaceSubClass");
		if (if_subclass != NULL)
			protocol = set_usb_mass_storage_ifsubtype(type_str, if_subclass, sizeof(type_str)-1);
	} else {
		set_usb_iftype(type_str, if_class_num, sizeof(type_str)-1);
	}

	info(udev, "%s: if_class %d protocol %d\n",
	     udev_device_get_syspath(dev_interface), if_class_num, protocol);

	/* usb device directory */
	dev_usb = udev_device_get_parent_with_subsystem(dev_interface, "usb");
	if (!dev_usb) {
		info(udev, "unable to find parent 'usb' device of '%s'\n",
		     udev_device_get_syspath(dev));
		return 1;
	}

	/* mass storage */
	if (protocol == 6 && !use_usb_info) {
		struct udev_device *dev_scsi;
		const char *scsi_model, *scsi_vendor, *scsi_type, *scsi_rev;
		int host, bus, target, lun;

		/* get scsi device */
		dev_scsi = udev_device_get_parent_with_subsystem(dev, "scsi");
		if (dev_scsi == NULL) {
			info(udev, "unable to find parent 'scsi' device of '%s'\n",
			     udev_device_get_syspath(dev));
			goto fallback;
		}
		if (sscanf(udev_device_get_sysname(dev_scsi), "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4) {
			info(udev, "invalid scsi device '%s'\n", udev_device_get_sysname(dev_scsi));
			goto fallback;
		}

		/* Generic SPC-2 device */
		scsi_vendor = udev_device_get_sysattr_value(dev_scsi, "vendor");
		if (!scsi_vendor) {
			info(udev, "%s: cannot get SCSI vendor attribute\n",
			     udev_device_get_sysname(dev_scsi));
			goto fallback;
		}
		udev_util_replace_whitespace(scsi_vendor, vendor_str, sizeof(vendor_str)-1);
		udev_util_replace_chars(vendor_str, NULL);

		scsi_model = udev_device_get_sysattr_value(dev_scsi, "model");
		if (!scsi_model) {
			info(udev, "%s: cannot get SCSI model attribute\n",
			     udev_device_get_sysname(dev_scsi));
			goto fallback;
		}
		udev_util_replace_whitespace(scsi_model, model_str, sizeof(model_str)-1);
		udev_util_replace_chars(model_str, NULL);

		scsi_type = udev_device_get_sysattr_value(dev_scsi, "type");
		if (!scsi_type) {
			info(udev, "%s: cannot get SCSI type attribute\n",
			     udev_device_get_sysname(dev_scsi));
			goto fallback;
		}
		set_scsi_type(type_str, scsi_type, sizeof(type_str)-1);

		scsi_rev = udev_device_get_sysattr_value(dev_scsi, "rev");
		if (!scsi_rev) {
			info(udev, "%s: cannot get SCSI revision attribute\n",
			     udev_device_get_sysname(dev_scsi));
			goto fallback;
		}
		udev_util_replace_whitespace(scsi_rev, revision_str, sizeof(revision_str)-1);
		udev_util_replace_chars(revision_str, NULL);

		/*
		 * some broken devices have the same identifiers
		 * for all luns, export the target:lun number
		 */
		sprintf(instance_str, "%d:%d", target, lun);
	}

fallback:
	/* fallback to USB vendor & device */
	if (vendor_str[0] == '\0') {
		const char *usb_vendor = NULL;

		if (!use_num_info)
			usb_vendor = udev_device_get_sysattr_value(dev_usb, "manufacturer");

		if (!usb_vendor)
			usb_vendor = udev_device_get_sysattr_value(dev_usb, "idVendor");

		if (!usb_vendor) {
			info(udev, "No USB vendor information available\n");
			return 1;
		}
		udev_util_replace_whitespace(usb_vendor, vendor_str, sizeof(vendor_str)-1);
		udev_util_replace_chars(vendor_str, NULL);
	}

	if (model_str[0] == '\0') {
		const char *usb_model = NULL;

		if (!use_num_info)
			usb_model = udev_device_get_sysattr_value(dev_usb, "product");

		if (!usb_model)
			usb_model = udev_device_get_sysattr_value(dev_usb, "idProduct");

		if (!usb_model) {
			dbg(udev, "No USB model information available\n");
			return 1;
		}
		udev_util_replace_whitespace(usb_model, model_str, sizeof(model_str)-1);
		udev_util_replace_chars(model_str, NULL);
	}

	if (revision_str[0] == '\0') {
		const char *usb_rev;

		usb_rev = udev_device_get_sysattr_value(dev_usb, "bcdDevice");
		if (usb_rev) {
			udev_util_replace_whitespace(usb_rev, revision_str, sizeof(revision_str)-1);
			udev_util_replace_chars(revision_str, NULL);
		}
	}

	if (serial_str[0] == '\0') {
		const char *usb_serial;

		usb_serial = udev_device_get_sysattr_value(dev_usb, "serial");
		if (usb_serial) {
			udev_util_replace_whitespace(usb_serial, serial_str, sizeof(serial_str)-1);
			udev_util_replace_chars(serial_str, NULL);
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "usb-info", no_argument, NULL, 'u' },
		{ "num-info", no_argument, NULL, 'n' },
		{ "export", no_argument, NULL, 'x' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	struct udev *udev;
	struct udev_device *dev = NULL;
	char syspath[UTIL_PATH_SIZE];
	const char *devpath;
	static int export;
	int retval = 0;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	logging_init("usb_id");
	udev_set_log_fn(udev, log_fn);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dnuxh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
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
		case 'h':
			printf("Usage: usb_id [--usb-info] [--num-info] [--export] [--help] <devpath>\n"
			       "  --usb-info  use usb strings instead\n"
			       "  --num-info  use numerical values\n"
			       "  --export    print values as environemt keys\n"
			       "  --help      print this help text\n\n");
		default:
			retval = 1;
			goto exit;
		}
	}

	devpath = getenv("DEVPATH");
	if (devpath == NULL)
		devpath = argv[optind];
	if (devpath == NULL) {
		fprintf(stderr, "No device specified\n");
		retval = 1;
		goto exit;
	}

	util_strlcpy(syspath, udev_get_sys_path(udev), sizeof(syspath));
	util_strlcat(syspath, devpath, sizeof(syspath));
	dev = udev_device_new_from_syspath(udev, syspath);
	if (dev == NULL) {
		err(udev, "unable to access '%s'\n", devpath);
		return 1;
	}

	retval = usb_id(dev);
	if (retval == 0) {
		char serial[256];

		util_strlcpy(serial, vendor_str, sizeof(serial));
		util_strlcat(serial, "_", sizeof(serial));
		util_strlcat(serial, model_str, sizeof(serial));
		if (serial_str[0] != '\0') {
			util_strlcat(serial, "_", sizeof(serial));
			util_strlcat(serial, serial_str, sizeof(serial));
		}
		if (instance_str[0] != '\0') {
			util_strlcat(serial, "-", sizeof(serial));
			util_strlcat(serial, instance_str, sizeof(serial));
		}

		if (export) {
			printf("ID_VENDOR=%s\n", vendor_str);
			printf("ID_MODEL=%s\n", model_str);
			printf("ID_REVISION=%s\n", revision_str);
			printf("ID_SERIAL=%s\n", serial);
			if (serial_str[0] != '\0')
				printf("ID_SERIAL_SHORT=%s\n", serial_str);
			printf("ID_TYPE=%s\n", type_str);
			if (instance_str[0] != '\0')
				printf("ID_INSTANCE=%s\n", instance_str);
			printf("ID_BUS=usb\n");
		} else
			printf("%s\n", serial);
	}

exit:
	udev_device_unref(dev);
	udev_unref(udev);
	logging_close();
	return retval;
}
