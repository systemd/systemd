/*
 * scsi_id.h
 *
 * General defines and such for scsi_id
 *
 * Copyright (C) IBM Corp. 2003
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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
			    int page_code, char *serial, char *serial_short, int len);

/*
 * Page code values. 
 */
enum page_code {
		PAGE_83_PRE_SPC3 = -0x83,
		PAGE_UNSPECIFIED = 0x00,
		PAGE_80		 = 0x80,
		PAGE_83		 = 0x83,
};
