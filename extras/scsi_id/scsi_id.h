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
	log_message(LOG_DEBUG, "%s: " format, __FUNCTION__, ## arg)

#define	MAX_NAME_LEN	72
#define OFFSET (2 * sizeof(unsigned int))

static inline char *sysfs_get_attr(struct sysfs_class_device *dev,
				    const char *attr)
{
	return sysfs_get_value_from_attributes(dev->directory->attributes,
					       attr);
}

extern int scsi_get_serial (struct sysfs_class_device *scsi_dev,
			    const char *devname, int page_code, char *serial,
			    int len);
extern void log_message (int level, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

