/* 
 * chassis_id.c
 *
 * Copyright (C) 2004 Intel Corporation.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v 2.0 as published by the Free Software Foundation; 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 * Authors: Atul Sabharwal
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "chassis_id.h"

//#define DEBUG              1

/* Run SCSI id to find serial number of the device */
static int getserial_number(char * devpath, char * snumber)
{
	FILE *fp;
	char vendor[255], model[255], cmd[255];
	int retval;

	sprintf(cmd, "/sbin/scsi_id -s %s -p 0x80", devpath);

	fp = popen(cmd, "r");

	if (fp == NULL)
		return -ERROR_BAD_SNUMBER;

	fscanf(fp, "%s %s %s", vendor, model, snumber);
	#ifdef DEBUG
	syslog(LOG_PID| LOG_DAEMON| LOG_ERR, "\n%s", snumber );
	#endif

	retval = pclose(fp);
	if (retval == -1)
		return -ERROR_BAD_SNUMBER;
	else
		return NO_ERROR;
}

int main(int argc, char **argv, char **envp)
{
	int chassis_num, slot_num, retval;
	char disk_snum[255], devpath[255];
	char *ptr;
	int disk_index;

	syslog( LOG_PID| LOG_DAEMON| LOG_ERR, "\n%s", "starting chassis_id" );

	ptr = getenv("DEVPATH");
	if (ptr == NULL)
		return -ERROR_NO_DEVPATH;

	sscanf(ptr, "%s", &devpath[0]);
	#ifdef DEBUG
	syslog(LOG_PID|LOG_DAEMON| LOG_ERR, "Devpath %s", devpath);
	#endif

	retval = table_init();
	if (retval < 0)
	return -ERROR_BAD_TABLE;

	getserial_number(devpath, disk_snum);

	/* Now we open the provisioning table t find actual entry for the serial number*/
	disk_index =  table_find_disk(disk_snum, &chassis_num, &slot_num);
	if ( disk_index == -1 ) {
		// typical provisioning error
		return -ERROR_NO_DISK;
	} else {
		table_select_disk( disk_index );
	}
	return 0;
}
