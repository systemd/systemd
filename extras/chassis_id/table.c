/* 
 * table.c
 *
 * Copyright (C) 2004 Intel Corporation.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2.0 as published by the Free Software Foundation; 
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

#define TABLE_SIZE 100
#define PROVISION_DB  "/usr/local/bin/provision.tbl"

struct provision_record
{
	int  id;
	int  num_disks;
	int  chassis_num;
	int  slot_num;
	char serial_num[32];
	char name[32];
} ptable[TABLE_SIZE];

int ptable_size;

/* Initialize the provisioning table by reading the data from special file provision.tbl *
   Return error if something does not work appropriately.                                */
int table_init()
{
	FILE *fp;
	char ptr[255];
	int i;

	fp = fopen( PROVISION_DB, "r");

	if ((fp== NULL) || feof(fp))
		 return -1;

	// skip the first line of text which contains descriptive details.
	fgets(ptr, 80, fp);	
	i = 0;
	while (!feof(fp)) {
		fgets(ptr, 80, fp);	
		sscanf(ptr, "%d %d %d %d %d %s %s", &ptable[i].id,
			&ptable[i].num_disks, 
			&ptable[i].chassis_num, &ptable[i].slot_num,
			ptable[i].serial_num, ptable[i].name);
		i++;       
	}  

	ptable_size = i;
	fclose(fp);
	return 0;
}


/* return -1 when no disk found. Otherwise return index of disk */
int table_find_disk( char * serialnumber , int * host_num, int * chassis_num, int *slot_num)
{
	int i;

	for (i = 0; i < ptable_size; i++) {
		if (strcmp(ptable[i].serial_num, serialnumber) == 0) {
			*chassis_num =  ptable[i].chassis_num;
			*slot_num = ptable[i].slot_num;
			break;
		}
	}

	if (i == ptable_size)
		return -1;
	else
		return i;
}

/* This function is primarily there for passing the selected disk entry to udev
 * so that it can create descriptive GDN for it. So, for that we need to output
 * this data to stdout.
 */
int table_select_disk( int diskindex )
{
	printf("%d ", ptable[diskindex].chassis_num);
	printf("%d ", ptable[diskindex].slot_num);
	printf("%s ", ptable[diskindex].name);
}

