/*
 * Copyright (C) IBM Corp. 2003
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

#pragma once

#define MAX_PATH_LEN 512

/*
 * MAX_ATTR_LEN: maximum length of the result of reading a sysfs
 * attribute.
 */
#define MAX_ATTR_LEN 256

/*
 * MAX_SERIAL_LEN: the maximum length of the serial number, including
 * added prefixes such as vendor and product (model) strings.
 */
#define MAX_SERIAL_LEN 256

/*
 * MAX_BUFFER_LEN: maximum buffer size and line length used while reading
 * the config file.
 */
#define MAX_BUFFER_LEN 256

struct scsi_id_device {
        char vendor[9];
        char model[17];
        char revision[5];
        char type[33];
        char kernel[64];
        char serial[MAX_SERIAL_LEN];
        char serial_short[MAX_SERIAL_LEN];
        int use_sg;

        /* Always from page 0x80 e.g. 'B3G1P8500RWT' - may not be unique */
        char unit_serial_number[MAX_SERIAL_LEN];

        /* NULs if not set - otherwise hex encoding using lower-case e.g. '50014ee0016eb572' */
        char wwn[17];

        /* NULs if not set - otherwise hex encoding using lower-case e.g. '0xe00000d80000' */
        char wwn_vendor_extension[17];

        /* NULs if not set - otherwise decimal number */
        char tgpt_group[8];
};

int scsi_std_inquiry(struct udev *udev, struct scsi_id_device *dev_scsi, const char *devname);
int scsi_get_serial(struct udev *udev, struct scsi_id_device *dev_scsi, const char *devname,
                    int page_code, int len);

/*
 * Page code values.
 */
enum page_code {
        PAGE_83_PRE_SPC3 = -0x83,
        PAGE_UNSPECIFIED = 0x00,
        PAGE_80          = 0x80,
        PAGE_83          = 0x83,
};
