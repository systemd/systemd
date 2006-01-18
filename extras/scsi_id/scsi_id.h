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

#define	MAX_PATH_LEN	512

/*
 * MAX_ATTR_LEN: maximum length of the result of reading a sysfs
 * attribute.
 */
#define	MAX_ATTR_LEN	256

/*
 * MAX_SERIAL_LEN: the maximum length of the serial number, including
 * added prefixes such as vendor and product (model) strings.
 */
#define	MAX_SERIAL_LEN	256

/*
 * MAX_BUFFER_LEN: maximum buffer size and line length used while reading
 * the config file.
 */
#define MAX_BUFFER_LEN	256

extern int scsi_get_serial (struct sysfs_device *dev_scsi, const char *devname,
			    int page_code, char *serial, int len);

/*
 * Page code values. 
 */
enum page_code {
		PAGE_83_PRE_SPC3 = -0x83,
		PAGE_UNSPECIFIED = 0x00,
		PAGE_80		 = 0x80,
		PAGE_83		 = 0x83,
};
