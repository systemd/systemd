
  /* -*-c-*-: 
   **
   ** (C) 2003 Intel Corporation
   **          Atul Sabharwal <atul.sabharwal@intel.com>
   **
   ** $Id: chassis_id.c,v 1.8 2004/03/22 23:33:10 atul Exp $
   **
   ** Distributed under the terms of the GNU Public License, v2.0 or
   ** later.
   **
   ** Many parts heavily based on test-skeleton.c, by Ulrich Drepper;
   ** with his permission, they have been re-licensed GPL, and his
   ** copyright still applies on them. 
   **
   */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "chassis_id.h"

//#define DEBUG              1

int main(int argc, char **argv, char ** envp)
{
     int chassis_num, slot_num, retval, host_num;
     char disk_snum[255], devpath[255];
     char * ptr;
     int disk_index;

      syslog( LOG_PID| LOG_DAEMON| LOG_ERR, "\n%s", "starting chassis_id" );

#if 0
     ptr = (char *) getenv( "CHASSIS");
     if( ptr == NULL )
          return -ERROR_NO_CHASSIS;

     sscanf(ptr, "%d", &chassis_num);
     #ifdef DEBUG
        syslog(LOG_PID| LOG_DAEMON| LOG_ERR, "Chassis %d", chassis_num);
     #endif


     ptr = (char *) getenv( "SLOT" );
     if( ptr== NULL )
          return -ERROR_NO_SLOT;

     sscanf(ptr, "%d", &slot_num);
     #ifdef DEBUG
        syslog( LOG_PID|LOG_DAEMON| LOG_ERR, "Slot %d", slot_num);
     #endif
#endif
     ptr = (char *) getenv( "DEVPATH");
     if( ptr == NULL )
          return -ERROR_NO_DEVPATH;

     sscanf(ptr, "%s", &devpath[0]);
     #ifdef DEBUG
        syslog( LOG_PID|LOG_DAEMON| LOG_ERR, "Devpath %s", devpath);
     #endif

     retval = table_init();
     if(retval < 0 )
        return -ERROR_BAD_TABLE;
     
     getserial_number( devpath, disk_snum);
     

     /* Now we open the provisioning table t find actual entry for the serial number*/
     disk_index =  table_find_disk(disk_snum, &host_num, &chassis_num, &slot_num);
     if ( disk_index == -1 )
     {
        //typical provisioning error
        return -ERROR_NO_DISK;
     }
     else
     {
        table_select_disk( disk_index );
     }
     return 0;
}


/* Run SCSI id to find serial number of the device */
int getserial_number( char * devpath, char * snumber )
{
   FILE *fp; 
   char vendor [255], model[255], cmd[255];
   int retval;

   sprintf(cmd, "/sbin/scsi_id -s %s -p 0x80", devpath);

   fp = popen( cmd, "r");

   if (fp == NULL)
         return -ERROR_BAD_SNUMBER;

   fscanf( fp, "%s %s %s", vendor, model, snumber);
   #ifdef DEBUG
   	syslog( LOG_PID| LOG_DAEMON| LOG_ERR, "\n%s", snumber );
   #endif

   retval = pclose(fp);
   if (retval == -1)
         return -ERROR_BAD_SNUMBER;
   else
         return NO_ERROR;

}

