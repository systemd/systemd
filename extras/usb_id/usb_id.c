/*
 * usb_id - identify an USB device
 *
 * Copyright (c) 2005 SUSE Linux Products GmbH, Germany
 *
 * Author: Hannes Reinecke <hare@suse.de>
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
#include <getopt.h>

#include "libudev.h"
#include "libudev-private.h"

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
static char vendor_str_enc[256];
static const char *vendor_id = "";
static char model_str[64];
static char model_str_enc[256];
static const char *product_id = "";
static char serial_str[UTIL_NAME_SIZE];
static char packed_if_str[UTIL_NAME_SIZE];
static char revision_str[64];
static char type_str[64];
static char instance_str[64];
static const char *ifnum;
static const char *driver;

static int use_usb_info;
static int use_num_info;

static void set_usb_iftype(char *to, int if_class_num, size_t len)
{
	char *type = "generic";

	switch (if_class_num) {
	case 1:
		type = "audio";
		break;
	case 2: /* CDC-Control */
		break;
	case 3:
		type = "hid";
		break;
	case 5: /* Physical */
		break;
	case 6:
		type = "media";
		break;
	case 7:
		type = "printer";
		break;
	case 8:
		type = "storage";
		break;
	case 9:
		type = "hub";
		break;
	case 0x0a: /* CDC-Data */
		break;
	case 0x0b: /* Chip/Smart Card */
		break;
	case 0x0d: /* Content Security */
		break;
	case 0x0e:
		type = "video";
		break;
	case 0xdc: /* Diagnostic Device */
		break;
	case 0xe0: /* Wireless Controller */
		break;
	case 0xfe: /* Application-specific */
		break;
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
			type = "atapi";
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
	util_strscpy(to, len, type);
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
	util_strscpy(to, len, type);
}

#define USB_DT_DEVICE			0x01
#define USB_DT_INTERFACE		0x04

static int dev_if_packed_info(struct udev_device *dev, char *ifs_str, size_t len)
{
	char *filename = NULL;
	int fd;
	ssize_t size;
	unsigned char buf[18 + 65535];
	unsigned int pos, strpos;
	struct usb_interface_descriptor {
		u_int8_t	bLength;
		u_int8_t	bDescriptorType;
		u_int8_t	bInterfaceNumber;
		u_int8_t	bAlternateSetting;
		u_int8_t	bNumEndpoints;
		u_int8_t	bInterfaceClass;
		u_int8_t	bInterfaceSubClass;
		u_int8_t	bInterfaceProtocol;
		u_int8_t	iInterface;
	} __attribute__((packed));
	int err = 0;

	if (asprintf(&filename, "%s/descriptors", udev_device_get_syspath(dev)) < 0) {
		err = -1;
		goto out;
	}
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "error opening USB device 'descriptors' file\n");
		err = -1;
		goto out;
	}
	size = read(fd, buf, sizeof(buf));
	close(fd);
	if (size < 18 || size == sizeof(buf)) {
		err = -1;
		goto out;
	}

	pos = 0;
	strpos = 0;
	while (pos < sizeof(buf) && strpos+7 < len) {
		struct usb_interface_descriptor *desc;
		char if_str[8];

		desc = (struct usb_interface_descriptor *) &buf[pos];
		if (desc->bLength < 3)
			break;
		pos += desc->bLength;

		if (desc->bDescriptorType != USB_DT_INTERFACE)
			continue;

		if (snprintf(if_str, 8, "%02x%02x%02x:",
			     desc->bInterfaceClass,
			     desc->bInterfaceSubClass,
			     desc->bInterfaceProtocol) != 7)
			continue;

		if (strstr(ifs_str, if_str) != NULL)
			continue;

		memcpy(&ifs_str[strpos], if_str, 8),
		strpos += 7;
	}
out:
	free(filename);
	return err;
}

/*
 * A unique USB identification is generated like this:
 *
 * 1.) Get the USB device type from InterfaceClass and InterfaceSubClass
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
	struct udev_device *dev_interface = NULL;
	struct udev_device *dev_usb = NULL;
	const char *if_class, *if_subclass;
	int if_class_num;
	int protocol = 0;

	dbg(udev, "syspath %s\n", udev_device_get_syspath(dev));

	/* shortcut, if we are called directly for a "usb_device" type */
	if (udev_device_get_devtype(dev) != NULL && strcmp(udev_device_get_devtype(dev), "usb_device") == 0) {
		dev_if_packed_info(dev, packed_if_str, sizeof(packed_if_str));
		dev_usb = dev;
		goto fallback;
	}

	/* usb interface directory */
	dev_interface = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface");
	if (dev_interface == NULL) {
		info(udev, "unable to access usb_interface device of '%s'\n",
		     udev_device_get_syspath(dev));
		return 1;
	}

	ifnum = udev_device_get_sysattr_value(dev_interface, "bInterfaceNumber");
	driver = udev_device_get_sysattr_value(dev_interface, "driver");

	if_class = udev_device_get_sysattr_value(dev_interface, "bInterfaceClass");
	if (!if_class) {
		info(udev, "%s: cannot get bInterfaceClass attribute\n",
		     udev_device_get_sysname(dev));
		return 1;
	}

	if_class_num = strtoul(if_class, NULL, 16);
	if (if_class_num == 8) {
		/* mass storage */
		if_subclass = udev_device_get_sysattr_value(dev_interface, "bInterfaceSubClass");
		if (if_subclass != NULL)
			protocol = set_usb_mass_storage_ifsubtype(type_str, if_subclass, sizeof(type_str)-1);
	} else {
		set_usb_iftype(type_str, if_class_num, sizeof(type_str)-1);
	}

	info(udev, "%s: if_class %d protocol %d\n",
	     udev_device_get_syspath(dev_interface), if_class_num, protocol);

	/* usb device directory */
	dev_usb = udev_device_get_parent_with_subsystem_devtype(dev_interface, "usb", "usb_device");
	if (!dev_usb) {
		info(udev, "unable to find parent 'usb' device of '%s'\n",
		     udev_device_get_syspath(dev));
		return 1;
	}

	/* all interfaces of the device in a single string */
	dev_if_packed_info(dev_usb, packed_if_str, sizeof(packed_if_str));

	/* mass storage : SCSI or ATAPI */
	if ((protocol == 6 || protocol == 2) && !use_usb_info) {
		struct udev_device *dev_scsi;
		const char *scsi_model, *scsi_vendor, *scsi_type, *scsi_rev;
		int host, bus, target, lun;

		/* get scsi device */
		dev_scsi = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_device");
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
		udev_util_encode_string(scsi_vendor, vendor_str_enc, sizeof(vendor_str_enc));
		udev_util_replace_whitespace(scsi_vendor, vendor_str, sizeof(vendor_str)-1);
		udev_util_replace_chars(vendor_str, NULL);

		scsi_model = udev_device_get_sysattr_value(dev_scsi, "model");
		if (!scsi_model) {
			info(udev, "%s: cannot get SCSI model attribute\n",
			     udev_device_get_sysname(dev_scsi));
			goto fallback;
		}
		udev_util_encode_string(scsi_model, model_str_enc, sizeof(model_str_enc));
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
	vendor_id = udev_device_get_sysattr_value(dev_usb, "idVendor");
	product_id = udev_device_get_sysattr_value(dev_usb, "idProduct");

	/* fallback to USB vendor & device */
	if (vendor_str[0] == '\0') {
		const char *usb_vendor = NULL;

		if (!use_num_info)
			usb_vendor = udev_device_get_sysattr_value(dev_usb, "manufacturer");

		if (!usb_vendor)
			usb_vendor = vendor_id;

		if (!usb_vendor) {
			info(udev, "No USB vendor information available\n");
			return 1;
		}
		udev_util_encode_string(usb_vendor, vendor_str_enc, sizeof(vendor_str_enc));
		udev_util_replace_whitespace(usb_vendor, vendor_str, sizeof(vendor_str)-1);
		udev_util_replace_chars(vendor_str, NULL);
	}

	if (model_str[0] == '\0') {
		const char *usb_model = NULL;

		if (!use_num_info)
			usb_model = udev_device_get_sysattr_value(dev_usb, "product");

		if (!usb_model)
			usb_model = product_id;

		if (!usb_model) {
			dbg(udev, "No USB model information available\n");
			return 1;
		}
		udev_util_encode_string(usb_model, model_str_enc, sizeof(model_str_enc));
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
	static int export;
	int retval = 0;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("usb_id");
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
			printf("Usage: usb_id [--usb-info] [--num-info] [--export] [--help] [<devpath>]\n"
			       "  --usb-info  use usb strings instead\n"
			       "  --num-info  use numerical values\n"
			       "  --export    print values as environment keys\n"
			       "  --help      print this help text\n\n");
		default:
			retval = 1;
			goto exit;
		}
	}

	dev = udev_device_new_from_environment(udev);
	if (dev == NULL) {
		char syspath[UTIL_PATH_SIZE];
		const char *devpath;

		devpath = argv[optind];
		if (devpath == NULL) {
			fprintf(stderr, "missing device\n");
			retval = 1;
			goto exit;
		}

		util_strscpyl(syspath, sizeof(syspath), udev_get_sys_path(udev), devpath, NULL);
		dev = udev_device_new_from_syspath(udev, syspath);
		if (dev == NULL) {
			err(udev, "unable to access '%s'\n", devpath);
			retval = 1;
			goto exit;
			return 1;
		}
	}

	retval = usb_id(dev);
	if (retval == 0) {
		char serial[256];
		size_t l;
		char *s;

		s = serial;
		l = util_strpcpyl(&s, sizeof(serial), vendor_str, "_", model_str, NULL);
		if (serial_str[0] != '\0')
			l = util_strpcpyl(&s, l, "_", serial_str, NULL);
		if (instance_str[0] != '\0')
			util_strpcpyl(&s, l, "-", instance_str, NULL);

		if (export) {
			printf("ID_VENDOR=%s\n", vendor_str);
			printf("ID_VENDOR_ENC=%s\n", vendor_str_enc);
			printf("ID_VENDOR_ID=%s\n", vendor_id);
			printf("ID_MODEL=%s\n", model_str);
			printf("ID_MODEL_ENC=%s\n", model_str_enc);
			printf("ID_MODEL_ID=%s\n", product_id);
			printf("ID_REVISION=%s\n", revision_str);
			printf("ID_SERIAL=%s\n", serial);
			if (serial_str[0] != '\0')
				printf("ID_SERIAL_SHORT=%s\n", serial_str);
			if (type_str[0] != '\0')
				printf("ID_TYPE=%s\n", type_str);
			if (instance_str[0] != '\0')
				printf("ID_INSTANCE=%s\n", instance_str);
			printf("ID_BUS=usb\n");
			if (packed_if_str[0] != '\0')
				printf("ID_USB_INTERFACES=:%s\n", packed_if_str);
			if (ifnum != NULL)
				printf("ID_USB_INTERFACE_NUM=%s\n", ifnum);
			if (driver != NULL)
				printf("ID_USB_DRIVER=%s\n", driver);
		} else
			printf("%s\n", serial);
	}

exit:
	udev_device_unref(dev);
	udev_unref(udev);
	udev_log_close();
	return retval;
}
