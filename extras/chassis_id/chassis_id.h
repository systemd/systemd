/* 
 * chassis_id.h
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

#ifndef _CHASSIS_ID_H
#define _CHASSIS_ID_H

//#define DEBUG			1
#define ERROR			1
#define ERROR_NO_SLOT		2
#define ERROR_NO_CHASSIS	3
#define ERROR_NO_DEVPATH	4
#define ERROR_BAD_SNUMBER	5
#define ERROR_NO_DISK		6
#define ERROR_BAD_TABLE		7
#define ERROR_BAD_SCAN		8
#define NO_ERROR		0

extern int table_init(void);
extern int table_find_disk(const char *serialnumber , int *chassis_num, int *slot_num);
extern int table_select_disk(int diskindex);

#endif
