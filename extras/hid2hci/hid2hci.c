/*
 * hid2hci : switch the radio on devices that support
 *           it from HID to HCI and back
 *
 * Copyright (C) 2003-2009  Marcel Holtmann <marcel@holtmann.org>
 * Copyright (C) 2008-2009  Mario Limonciello <mario_limonciello@dell.com>
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/hiddev.h>
#include <usb.h>

#include "libudev.h"
#include "libudev-private.h"

enum mode {
	HCI = 0,
	HID = 1,
};

static int usb_switch_csr(struct usb_dev_handle *dev, enum mode mode)
{
	int err;

	err = usb_control_msg(dev,
			      USB_ENDPOINT_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
			      0, mode, 0, NULL, 0, 10000);
	if (err == 0) {
		err = -1;
		errno = EALREADY;
	} else {
		if (errno == ETIMEDOUT)
			err = 0;
	}
	return err;
}

static int hid_logitech_send_report(int fd, const char *buf, size_t size)
{
	struct hiddev_report_info rinfo;
	struct hiddev_usage_ref uref;
	unsigned int i;
	int err;

	for (i = 0; i < size; i++) {
		memset(&uref, 0, sizeof(uref));
		uref.report_type = HID_REPORT_TYPE_OUTPUT;
		uref.report_id   = 0x10;
		uref.field_index = 0;
		uref.usage_index = i;
		uref.usage_code  = 0xff000001;
		uref.value       = buf[i] & 0x000000ff;
		err = ioctl(fd, HIDIOCSUSAGE, &uref);
		if (err < 0)
			return err;
	}

	memset(&rinfo, 0, sizeof(rinfo));
	rinfo.report_type = HID_REPORT_TYPE_OUTPUT;
	rinfo.report_id   = 0x10;
	rinfo.num_fields  = 1;
	err = ioctl(fd, HIDIOCSREPORT, &rinfo);

	return err;
}

static int hid_switch_logitech(const char *filename)
{
	char rep1[] = { 0xff, 0x80, 0x80, 0x01, 0x00, 0x00 };
	char rep2[] = { 0xff, 0x80, 0x00, 0x00, 0x30, 0x00 };
	char rep3[] = { 0xff, 0x81, 0x80, 0x00, 0x00, 0x00 };
	int fd;
	int err = -1;

	fd = open(filename, O_RDWR);
	if (fd < 0)
		return err;

	err = ioctl(fd, HIDIOCINITREPORT, 0);
	if (err < 0)
		goto out;

	err = hid_logitech_send_report(fd, rep1, sizeof(rep1));
	if (err < 0)
		goto out;

	err = hid_logitech_send_report(fd, rep2, sizeof(rep2));
	if (err < 0)
		goto out;

	err = hid_logitech_send_report(fd, rep3, sizeof(rep3));
out:
	close(fd);
	return err;
}

static int usb_switch_dell(struct usb_dev_handle *dev, enum mode mode)
{
	char report[] = { 0x7f, 0x00, 0x00, 0x00 };
	int err;

	switch (mode) {
	case HCI:
		report[1] = 0x13;
		break;
	case HID:
		report[1] = 0x14;
		break;
	}

	/* Don't need to check return, as might not be in use */
	usb_detach_kernel_driver_np(dev, 0);

	if (usb_claim_interface(dev, 0) < 0)
		return -EIO;

	err = usb_control_msg(dev,
			USB_ENDPOINT_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
			USB_REQ_SET_CONFIGURATION, 0x7f | (0x03 << 8), 0,
			report, sizeof(report), 5000);

	if (err == 0) {
		err = -1;
		errno = EALREADY;
	} else {
		if (errno == ETIMEDOUT)
			err = 0;
	}
	return err;
}

/*
 * The braindead libusb needs to scan and open all devices, just to
 * to find the device we already have. This needs to be fixed in libusb
 * or it will be ripped out and we carry our own code.
 */
static struct usb_device *usb_device_open_from_udev(struct udev_device *usb_dev)
{
	struct usb_bus *bus;
	const char *str;
	int busnum;
	int devnum;

	str = udev_device_get_sysattr_value(usb_dev, "busnum");
	if (str == NULL)
		return NULL;
	busnum = strtol(str, NULL, 0);

	str = udev_device_get_sysattr_value(usb_dev, "devnum");
	if (str == NULL)
		return NULL;
	devnum = strtol(str, NULL, 0);

	usb_init();
	usb_find_busses();
	usb_find_devices();

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		struct usb_device *dev;

		if (strtol(bus->dirname, NULL, 10) != busnum)
			continue;

		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->devnum == devnum)
				return dev;
		}
	}

	return NULL;
}

static struct usb_dev_handle *find_device(struct udev_device *udev_dev)
{
	struct usb_device *dev;

	dev = usb_device_open_from_udev(udev_dev);
	if (dev == NULL)
		return NULL;
	return usb_open(dev);
}

static void usage(const char *error)
{
	if (error)
		fprintf(stderr,"\n%s\n", error);
	else
		printf("hid2hci - Bluetooth HID to HCI mode switching utility\n\n");

	printf("Usage: hid2hci [options]\n"
		"  --mode=               mode to switch to [hid|hci] (default hci)\n"
		"  --devpath=            sys device path\n"
		"  --method=             method to use to switch [csr|logitech-hid|dell]\n"
		"  --help\n\n");
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "mode", required_argument, NULL, 'm' },
		{ "devpath", required_argument, NULL, 'p' },
		{ "method", required_argument, NULL, 'M' },
		{ }
	};
	enum method {
		METHOD_UNDEF,
		METHOD_CSR,
		METHOD_LOGITECH_HID,
		METHOD_DELL,
	} method = METHOD_UNDEF;
	struct udev *udev;
	struct udev_device *udev_dev = NULL;
	char syspath[UTIL_PATH_SIZE];
	int (*usb_switch)(struct usb_dev_handle *dev, enum mode mode) = NULL;
	enum mode mode = HCI;
	const char *devpath = NULL;
	int err = -1;
	int rc = 1;

	for (;;) {
		int option;

		option = getopt_long(argc, argv, "m:p:M:qh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'm':
			if (!strcmp(optarg, "hid")) {
				mode = HID;
			} else if (!strcmp(optarg, "hci")) {
				mode = HCI;
			} else {
				usage("error: undefined radio mode\n");
				exit(1);
			}
			break;
		case 'p':
			devpath = optarg;
			break;
		case 'M':
			if (!strcmp(optarg, "csr")) {
				method = METHOD_CSR;
				usb_switch = usb_switch_csr;
			} else if (!strcmp(optarg, "logitech-hid")) {
				method = METHOD_LOGITECH_HID;
			} else if (!strcmp(optarg, "dell")) {
				method = METHOD_DELL;
				usb_switch = usb_switch_dell;
			} else {
				usage("error: undefined switching method\n");
				exit(1);
			}
			break;
		case 'h':
			usage(NULL);
		default:
			exit(1);
		}
	}

	if (!devpath || method == METHOD_UNDEF) {
		usage("error: --devpath= and --method= must be defined\n");
		exit(1);
	}

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	util_strscpyl(syspath, sizeof(syspath), udev_get_sys_path(udev), devpath, NULL);
	udev_dev = udev_device_new_from_syspath(udev, syspath);
	if (udev_dev == NULL) {
		fprintf(stderr, "error: could not find '%s'\n", devpath);
		goto exit;
	}

	switch (method) {
	case METHOD_CSR:
	case METHOD_DELL: {
		struct udev_device *dev;
		struct usb_dev_handle *handle;
		const char *type;

		/* get the parent usb_device if needed */
		dev = udev_dev;
		type = udev_device_get_devtype(dev);
		if (type == NULL || strcmp(type, "usb_device") != 0) {
			dev = udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device");
			if (dev == NULL) {
				fprintf(stderr, "error: could not find usb_device for '%s'\n", devpath);
				goto exit;
			}
		}

		handle = find_device(dev);
		if (handle == NULL) {
			fprintf(stderr, "error: unable to handle '%s'\n",
				udev_device_get_syspath(dev));
			goto exit;
		}
		err = usb_switch(handle, mode);
		break;
	}
	case METHOD_LOGITECH_HID: {
		const char *device;

		device = udev_device_get_devnode(udev_dev);
		if (device == NULL) {
			fprintf(stderr, "error: could not find hiddev device node\n");
			goto exit;
		}
		err = hid_switch_logitech(device);
		break;
	}
	default:
		break;
	}

	if (err < 0)
		fprintf(stderr, "error: switching device '%s' failed.\n",
			udev_device_get_syspath(udev_dev));
exit:
	udev_device_unref(udev_dev);
	udev_unref(udev);
	return rc;
}
