/*
 * scsi_id.h
 *
 * General defines and such for scsi_id
 *
 * Copyright (C) IBM Corp. 2003
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

#define dprintf(format, arg...) \
	log_message(LOG_DEBUG, "%s: " format, __FUNCTION__ , ## arg)

#define	MAX_NAME_LEN	72
#define OFFSET (2 * sizeof(unsigned int))

/*
 * MAX_ATTR_LEN: maximum length of the result of reading a sysfs
 * attribute.
 */
#define	MAX_ATTR_LEN	256

/*
 * MAX_SERIAL_LEN: the maximum length of the serial number, including
 * added prefixes such as vendor and product (model) strings.
 */
#define	MAX_SERIAL_LEN	128

/*
 * MAX_BUFFER_LEN: maximum buffer size and line length used while reading
 * the config file.
 */
#define MAX_BUFFER_LEN	256

extern int sysfs_get_attr(const char *devpath, const char *attr, char *value,
			  size_t bufsize);
extern int scsi_get_serial (struct sysfs_class_device *scsi_dev,
			    const char *devname, int page_code, char *serial,
			    int len);
extern void log_message (int level, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

#ifdef __KLIBC__
#define makedev(major, minor)  ((major) << 8) | (minor)
#endif

#ifndef u8
typedef unsigned char u8;
#endif
