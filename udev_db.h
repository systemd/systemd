/*
 * udev_db.h
 *
 * Copyright (C) 2003 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _UDEV_DB_H_
#define _UDEV_DB_H_


extern int udev_db_add_device(struct udevice *dev);
extern int udev_db_delete_device(struct udevice *dev);

extern int udev_db_get_device(struct udevice *udev, const char *devpath);
extern int udev_db_lookup_name(const char *name, char *devpath, size_t len);
extern int udev_db_get_all_entries(struct list_head *name_list);

#endif /* _UDEV_DB_H_ */
