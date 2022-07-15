/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"

int talk_initctl(char runlevel);

int parse_shutdown_time_spec(const char *t, usec_t *ret);

/* The init script exit codes for the LSB 'status' verb. (This is different from the 'start' verb, whose exit
   codes are defined in exit-status.h.)

   0       program is running or service is OK
   1       program is dead and /var/run pid file exists
   2       program is dead and /var/lock lock file exists
   3       program is not running
   4       program or service status is unknown
   5-99    reserved for future LSB use
   100-149 reserved for distribution use
   150-199 reserved for application use
   200-254 reserved

   https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html
*/
enum {
        EXIT_PROGRAM_RUNNING_OR_SERVICE_OK        = 0,
        EXIT_PROGRAM_DEAD_AND_PID_EXISTS          = 1,
        EXIT_PROGRAM_DEAD_AND_LOCK_FILE_EXISTS    = 2,
        EXIT_PROGRAM_NOT_RUNNING                  = 3,
        EXIT_PROGRAM_OR_SERVICES_STATUS_UNKNOWN   = 4,
};

int enable_sysv_units(const char *verb, char **args);

int action_to_runlevel(void) _pure_;
