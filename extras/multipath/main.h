/*
 * Soft:        Description here...
 *
 * Version:     $Id: main.h,v 0.0.1 2003/09/18 15:13:38 cvaroqui Exp $
 *
 * Author:      Copyright (C) 2003 Christophe Varoqui
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef _MAIN_H
#define _MAIN_H

/* local includes */
#include "sg_include.h"

/* exerpt from "sg_err.h" */
#define SCSI_CHECK_CONDITION 	0x2
#define SCSI_COMMAND_TERMINATED 0x22
#define SG_ERR_DRIVER_SENSE     0x08

/* exerpt from "scsi.h" */
#define SCSI_IOCTL_GET_IDLUN            0x5382
#define SCSI_IOCTL_GET_BUS_NUMBER       0x5386

/* global defs */
#define WWID_SIZE	33
#define SERIAL_SIZE	14
#define MAX_DEVS	128
#define MAX_MP		MAX_DEVS / 2
#define MAX_MP_PATHS	MAX_DEVS / 4
#define FILE_NAME_SIZE	256
#define DEF_TIMEOUT	60000
#define EBUFF_SZ	256
#define TUR_CMD_LEN	6
#define DM_TARGET	"multipath"

/* Storage controlers cpabilities */
#define FAILOVER	0
#define MULTIBUS	1
#define GROUP_BY_SERIAL	2

#define PINDEX(x,y)	mp[(x)].pindex[(y)]

/* global types */
struct scsi_idlun {
	int dev_id;
	int host_unique_id;
	int host_no;
};

struct sg_id {
	int host_no;
	int channel;
	int scsi_id;
	int lun;
	int scsi_type;
	short h_cmd_per_lun;
	short d_queue_depth;
	int unused1;
	int unused2;
};

struct scsi_dev {
	char dev[FILE_NAME_SIZE];
	struct scsi_idlun scsi_id;
	int host_no;
};

struct path {
	char dev[FILE_NAME_SIZE];
	char sg_dev[FILE_NAME_SIZE];
	struct scsi_idlun scsi_id;
	struct sg_id sg_id;
	char wwid[WWID_SIZE];
	char vendor_id[8];
	char product_id[16];
	char rev[4];
	char serial[SERIAL_SIZE];
	int iopolicy;
};

struct multipath {
	char wwid[WWID_SIZE];
	int npaths;
	long size;
	int pindex[MAX_MP_PATHS];
};

struct env {
	int max_devs;
	int verbose;
	int quiet;
	int dry_run;
	int iopolicy;
	int with_sysfs;
	int dm_path_test_int;
	char sysfs_path[FILE_NAME_SIZE];
	char hotplugdev[FILE_NAME_SIZE];
};

/* Build version */
#define PROG    "multipath"

#define VERSION_CODE 0x000010
#define DATE_CODE    0x0C1503

#define MULTIPATH_VERSION(version)	\
	(version >> 16) & 0xFF,		\
	(version >> 8) & 0xFF,		\
	version & 0xFF

#define VERSION_STRING PROG" v%d.%d.%d (%.2d/%.2d, 20%.2d)\n",	\
                MULTIPATH_VERSION(VERSION_CODE),		\
                MULTIPATH_VERSION(DATE_CODE)

#endif
