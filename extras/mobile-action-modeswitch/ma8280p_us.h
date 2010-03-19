/*
 * Modem mode switcher
 *
 * Copyright (C) 2009  Dan Williams <dcbw@redhat.com>
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

#ifndef __MA8280P_H__
#define __MA8280P_H__

#include <usb.h>

int ma8280p_switch (struct usb_dev_handle *devh, struct usb_device *dev);

#endif  /* __MA8280P_H__ */
