/*
 * Modem mode switcher
 *
 * Copyright (C) 2008  Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2008  Peter Henn <support@option.com>
 *
 * Heavily based on the 'ozerocdoff' tool by Peter Henn.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details:
 */

#include <usb.h>

#include "utils.h"
#include "option.h"

/* Borrowed from /usr/include/linux/usb/ch9.h */
#define USB_ENDPOINT_XFERTYPE_MASK      0x03    /* in bmAttributes */
#define USB_ENDPOINT_XFER_BULK          2
#define USB_ENDPOINT_DIR_MASK           0x80
#define USB_DIR_OUT                     0       /* to device */
#define USB_DIR_IN                      0x80    /* to host */

struct usb_device *
option_zerocd_find (int vid, int pid)
{
	struct usb_bus *bus;
	struct usb_device *dev;

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == vid && dev->descriptor.idProduct == pid) {
				debug ("Found mass storage device:");
				debug ("  Endpoints: %d", dev->config[0].interface[0].altsetting[0].bNumEndpoints);
				debug ("  Class:     0x%X", dev->config[0].interface[0].altsetting[0].bInterfaceClass);
				debug ("  SubClass:  0x%X", dev->config[0].interface[0].altsetting[0].bInterfaceSubClass);
				debug ("  Protocol:  0x%X", dev->config[0].interface[0].altsetting[0].bInterfaceProtocol);

				if (   (dev->config[0].interface[0].altsetting[0].bNumEndpoints == 2)
				    && (dev->config[0].interface[0].altsetting[0].bInterfaceClass == 0x08)
				    && (dev->config[0].interface[0].altsetting[0].bInterfaceSubClass == 0x06)
				    && (dev->config[0].interface[0].altsetting[0].bInterfaceProtocol == 0x50) ) {
					debug ("Found modem mass storage device '%s'", dev->filename);
					return dev;
				}
			}
		}
	}
	return NULL;
}

static int
find_endpoints (struct usb_device *dev, int *in_ep, int *out_ep)
{
	int i;

	for (i = 0; i < dev->config[0].interface[0].altsetting[0].bNumEndpoints; i++) {
		struct usb_endpoint_descriptor *ep = &(dev->config[0].interface[0].altsetting[0].endpoint[i]);

		if ((ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK) {
			unsigned int direction = ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK;

			if (!*out_ep && (direction == USB_DIR_OUT))
				*out_ep = ep->bEndpointAddress;
			else if (!*in_ep && (direction == USB_DIR_IN))
				*in_ep = ep->bEndpointAddress;
		}

		if (*in_ep && *out_ep)
			return 0;
	}

	return -1;
}

int
option_zerocd_switch (struct usb_dev_handle *dh, struct usb_device *dev)
{
	const char const rezero_cbw[] = {
		0x55, 0x53, 0x42, 0x43, /* bulk command signature (LE) */
		0x78, 0x56, 0x34, 0x12, /* bulk command host tag */
		0x01, 0x00, 0x00, 0x00, /* bulk command data transfer length (LE) */
		0x80,                   /* flags: direction data-in */
		0x00,                   /* LUN */
		0x06,                   /* SCSI command length */
		0x01,                   /* SCSI command: REZERO */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* filler */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	int ret = -1, ep_in = 0, ep_out = 0;
	char buffer[256];

	/* Find the device's bulk in and out endpoints */
	if (find_endpoints (dev, &ep_in, &ep_out) < 0) {
		debug ("%s: couldn't find correct USB endpoints.", dev->filename);
		goto out;
	}

	usb_clear_halt (dh, ep_out);
	ret = usb_set_altinterface (dh, 0);
	if (ret != 0) {
		debug ("%s: couldn't set device alternate interface.", dev->filename);
		goto out;
	}

	/* Let the mass storage device settle */
	sleep (1);

	/* Send the modeswitch command */
	ret = usb_bulk_write (dh, ep_out, (char *) rezero_cbw, sizeof (rezero_cbw), 1000);
	if (ret < 0)
		return ret;

	debug ("%s: REZERO command sent.", dev->filename);

	/* Some devices need to be read from */
	ret = usb_bulk_read (dh, ep_in, buffer, sizeof (buffer), 1000);

out:
	return ret;
}

