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

#ifndef __OPTION_H__
#define __OPTION_H__

#include <usb.h>

struct usb_device *option_zerocd_find (int vid, int pid);

int option_zerocd_switch (struct usb_dev_handle *dh, struct usb_device *dev);

#endif  /* __OPTION_H__ */
