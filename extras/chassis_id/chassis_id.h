/* -*-c-*-: 
 **
 ** (C) 2003 Intel Corporation
 **          Atul Sabharwal <atul.sabharwal@intel.com>
 **
 ** Distributed under the terms of the GNU Public License, v2.0 or
 ** later.
 **
 ** Many parts heavily based on test-skeleton.c, by Ulrich Drepper;
 ** with his permission, they have been re-licensed GPL, and his
 ** copyright still applies on them. 
 **
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

extern int table_init();

#endif
