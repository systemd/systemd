/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * Copyright © IBM Corp. 2003
 */

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
        char kernel[64];
        char serial[MAX_SERIAL_LEN];
        char serial_short[MAX_SERIAL_LEN];
        unsigned type;
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

int scsi_std_inquiry(struct scsi_id_device *dev_scsi, const char *devname);
int scsi_get_serial(struct scsi_id_device *dev_scsi, const char *devname,
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
