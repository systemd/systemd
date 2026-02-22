/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdmessageshfoo
#define foosdmessageshfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include "_sd-common.h"
#include "sd-id128.h"

_SD_BEGIN_DECLARATIONS;

/* Hey! If you add a new message here, you *must* also update the message catalog with an appropriate explanation */

/* And if you add a new ID here, make sure to generate a random one with "systemd-id128 new". Do not use any
 * other IDs, and do not count them up manually. */

#define SD_MESSAGE_JOURNAL_START                      SD_ID128_MAKE(f7,73,79,a8,49,0b,40,8b,be,5f,69,40,50,5a,77,7b)
#define SD_MESSAGE_JOURNAL_START_STR                  SD_ID128_MAKE_STR(f7,73,79,a8,49,0b,40,8b,be,5f,69,40,50,5a,77,7b)
#define SD_MESSAGE_JOURNAL_STOP                       SD_ID128_MAKE(d9,3f,b3,c9,c2,4d,45,1a,97,ce,a6,15,ce,59,c0,0b)
#define SD_MESSAGE_JOURNAL_STOP_STR                   SD_ID128_MAKE_STR(d9,3f,b3,c9,c2,4d,45,1a,97,ce,a6,15,ce,59,c0,0b)
#define SD_MESSAGE_JOURNAL_DROPPED                    SD_ID128_MAKE(a5,96,d6,fe,7b,fa,49,94,82,8e,72,30,9e,95,d6,1e)
#define SD_MESSAGE_JOURNAL_DROPPED_STR                SD_ID128_MAKE_STR(a5,96,d6,fe,7b,fa,49,94,82,8e,72,30,9e,95,d6,1e)
#define SD_MESSAGE_JOURNAL_MISSED                     SD_ID128_MAKE(e9,bf,28,e6,e8,34,48,1b,b6,f4,8f,54,8a,d1,36,06)
#define SD_MESSAGE_JOURNAL_MISSED_STR                 SD_ID128_MAKE_STR(e9,bf,28,e6,e8,34,48,1b,b6,f4,8f,54,8a,d1,36,06)
#define SD_MESSAGE_JOURNAL_USAGE                      SD_ID128_MAKE(ec,38,7f,57,7b,84,4b,8f,a9,48,f3,3c,ad,9a,75,e6)
#define SD_MESSAGE_JOURNAL_USAGE_STR                  SD_ID128_MAKE_STR(ec,38,7f,57,7b,84,4b,8f,a9,48,f3,3c,ad,9a,75,e6)

#define SD_MESSAGE_COREDUMP                           SD_ID128_MAKE(fc,2e,22,bc,6e,e6,47,b6,b9,07,29,ab,34,a2,50,b1)
#define SD_MESSAGE_COREDUMP_STR                       SD_ID128_MAKE_STR(fc,2e,22,bc,6e,e6,47,b6,b9,07,29,ab,34,a2,50,b1)
#define SD_MESSAGE_TRUNCATED_CORE                     SD_ID128_MAKE(5a,ad,d8,e9,54,dc,4b,1a,8c,95,4d,63,fd,9e,11,37)
#define SD_MESSAGE_TRUNCATED_CORE_STR                 SD_ID128_MAKE_STR(5a,ad,d8,e9,54,dc,4b,1a,8c,95,4d,63,fd,9e,11,37)
#define SD_MESSAGE_BACKTRACE                          SD_ID128_MAKE(1f,4e,0a,44,a8,86,49,93,9a,ae,a3,4f,c6,da,8c,95)
#define SD_MESSAGE_BACKTRACE_STR                      SD_ID128_MAKE_STR(1f,4e,0a,44,a8,86,49,93,9a,ae,a3,4f,c6,da,8c,95)

#define SD_MESSAGE_SESSION_START                      SD_ID128_MAKE(8d,45,62,0c,1a,43,48,db,b1,74,10,da,57,c6,0c,66)
#define SD_MESSAGE_SESSION_START_STR                  SD_ID128_MAKE_STR(8d,45,62,0c,1a,43,48,db,b1,74,10,da,57,c6,0c,66)
#define SD_MESSAGE_SESSION_STOP                       SD_ID128_MAKE(33,54,93,94,24,b4,45,6d,98,02,ca,83,33,ed,42,4a)
#define SD_MESSAGE_SESSION_STOP_STR                   SD_ID128_MAKE_STR(33,54,93,94,24,b4,45,6d,98,02,ca,83,33,ed,42,4a)
#define SD_MESSAGE_SEAT_START                         SD_ID128_MAKE(fc,be,fc,5d,a2,3d,42,80,93,f9,7c,82,a9,29,0f,7b)
#define SD_MESSAGE_SEAT_START_STR                     SD_ID128_MAKE_STR(fc,be,fc,5d,a2,3d,42,80,93,f9,7c,82,a9,29,0f,7b)
#define SD_MESSAGE_SEAT_STOP                          SD_ID128_MAKE(e7,85,2b,fe,46,78,4e,d0,ac,cd,e0,4b,c8,64,c2,d5)
#define SD_MESSAGE_SEAT_STOP_STR                      SD_ID128_MAKE_STR(e7,85,2b,fe,46,78,4e,d0,ac,cd,e0,4b,c8,64,c2,d5)
#define SD_MESSAGE_MACHINE_START                      SD_ID128_MAKE(24,d8,d4,45,25,73,40,24,96,06,83,81,a6,31,2d,f2)
#define SD_MESSAGE_MACHINE_START_STR                  SD_ID128_MAKE_STR(24,d8,d4,45,25,73,40,24,96,06,83,81,a6,31,2d,f2)
#define SD_MESSAGE_MACHINE_STOP                       SD_ID128_MAKE(58,43,2b,d3,ba,ce,47,7c,b5,14,b5,63,81,b8,a7,58)
#define SD_MESSAGE_MACHINE_STOP_STR                   SD_ID128_MAKE_STR(58,43,2b,d3,ba,ce,47,7c,b5,14,b5,63,81,b8,a7,58)

#define SD_MESSAGE_TIME_CHANGE                        SD_ID128_MAKE(c7,a7,87,07,9b,35,4e,aa,a9,e7,7b,37,18,93,cd,27)
#define SD_MESSAGE_TIME_CHANGE_STR                    SD_ID128_MAKE_STR(c7,a7,87,07,9b,35,4e,aa,a9,e7,7b,37,18,93,cd,27)
#define SD_MESSAGE_TIMEZONE_CHANGE                    SD_ID128_MAKE(45,f8,2f,4a,ef,7a,4b,bf,94,2c,e8,61,d1,f2,09,90)
#define SD_MESSAGE_TIMEZONE_CHANGE_STR                SD_ID128_MAKE_STR(45,f8,2f,4a,ef,7a,4b,bf,94,2c,e8,61,d1,f2,09,90)

#define SD_MESSAGE_TAINTED                            SD_ID128_MAKE(50,87,6a,9d,b0,0f,4c,40,bd,e1,a2,ad,38,1c,3a,1b)
#define SD_MESSAGE_TAINTED_STR                        SD_ID128_MAKE_STR(50,87,6a,9d,b0,0f,4c,40,bd,e1,a2,ad,38,1c,3a,1b)
#define SD_MESSAGE_STARTUP_FINISHED                   SD_ID128_MAKE(b0,7a,24,9c,d0,24,41,4a,82,dd,00,cd,18,13,78,ff)
#define SD_MESSAGE_STARTUP_FINISHED_STR               SD_ID128_MAKE_STR(b0,7a,24,9c,d0,24,41,4a,82,dd,00,cd,18,13,78,ff)
#define SD_MESSAGE_USER_STARTUP_FINISHED              SD_ID128_MAKE(ee,d0,0a,68,ff,d8,4e,31,88,21,05,fd,97,3a,bd,d1)
#define SD_MESSAGE_USER_STARTUP_FINISHED_STR          SD_ID128_MAKE_STR(ee,d0,0a,68,ff,d8,4e,31,88,21,05,fd,97,3a,bd,d1)

#define SD_MESSAGE_SLEEP_START                        SD_ID128_MAKE(6b,bd,95,ee,97,79,41,e4,97,c4,8b,e2,7c,25,41,28)
#define SD_MESSAGE_SLEEP_START_STR                    SD_ID128_MAKE_STR(6b,bd,95,ee,97,79,41,e4,97,c4,8b,e2,7c,25,41,28)
#define SD_MESSAGE_SLEEP_STOP                         SD_ID128_MAKE(88,11,e6,df,2a,8e,40,f5,8a,94,ce,a2,6f,8e,bf,14)
#define SD_MESSAGE_SLEEP_STOP_STR                     SD_ID128_MAKE_STR(88,11,e6,df,2a,8e,40,f5,8a,94,ce,a2,6f,8e,bf,14)

#define SD_MESSAGE_SHUTDOWN                           SD_ID128_MAKE(98,26,88,66,d1,d5,4a,49,9c,4e,98,92,1d,93,bc,40)
#define SD_MESSAGE_SHUTDOWN_STR                       SD_ID128_MAKE_STR(98,26,88,66,d1,d5,4a,49,9c,4e,98,92,1d,93,bc,40)

#define SD_MESSAGE_FACTORY_RESET                      SD_ID128_MAKE(c1,4a,af,76,ec,28,4a,5f,a1,f1,05,f8,8d,fb,06,1c)
#define SD_MESSAGE_FACTORY_RESET_STR                  SD_ID128_MAKE_STR(c1,4a,af,76,ec,28,4a,5f,a1,f1,05,f8,8d,fb,06,1c)

#define SD_MESSAGE_CRASH_EXIT                         SD_ID128_MAKE(d9,ec,5e,95,e4,b6,46,aa,ae,a2,fd,05,21,4e,db,da)
#define SD_MESSAGE_CRASH_EXIT_STR                     SD_ID128_MAKE_STR(d9,ec,5e,95,e4,b6,46,aa,ae,a2,fd,05,21,4e,db,da)
#define SD_MESSAGE_CRASH_FAILED                       SD_ID128_MAKE(3e,d0,16,3e,86,8a,44,17,ab,8b,9e,21,04,07,a9,6c)
#define SD_MESSAGE_CRASH_FAILED_STR                   SD_ID128_MAKE_STR(3e,d0,16,3e,86,8a,44,17,ab,8b,9e,21,04,07,a9,6c)
#define SD_MESSAGE_CRASH_FREEZE                       SD_ID128_MAKE(64,5c,73,55,37,63,4a,e0,a3,2b,15,a7,c6,cb,a7,d4)
#define SD_MESSAGE_CRASH_FREEZE_STR                   SD_ID128_MAKE_STR(64,5c,73,55,37,63,4a,e0,a3,2b,15,a7,c6,cb,a7,d4)

#define SD_MESSAGE_CRASH_NO_COREDUMP                  SD_ID128_MAKE(5a,dd,b3,a0,6a,73,4d,33,96,b7,94,bf,98,fb,2d,01)
#define SD_MESSAGE_CRASH_NO_COREDUMP_STR              SD_ID128_MAKE_STR(5a,dd,b3,a0,6a,73,4d,33,96,b7,94,bf,98,fb,2d,01)
#define SD_MESSAGE_CRASH_NO_FORK                      SD_ID128_MAKE(5c,9e,98,de,4a,b9,4c,6a,9d,04,d0,ad,79,3b,d9,03)
#define SD_MESSAGE_CRASH_NO_FORK_STR                  SD_ID128_MAKE_STR(5c,9e,98,de,4a,b9,4c,6a,9d,04,d0,ad,79,3b,d9,03)
#define SD_MESSAGE_CRASH_UNKNOWN_SIGNAL               SD_ID128_MAKE(5e,6f,1f,5e,4d,b6,4a,0e,ae,e3,36,82,49,d2,0b,94)
#define SD_MESSAGE_CRASH_UNKNOWN_SIGNAL_STR           SD_ID128_MAKE_STR(5e,6f,1f,5e,4d,b6,4a,0e,ae,e3,36,82,49,d2,0b,94)
#define SD_MESSAGE_CRASH_SYSTEMD_SIGNAL               SD_ID128_MAKE(83,f8,4b,35,ee,26,4f,74,a3,89,6a,97,17,af,34,cb)
#define SD_MESSAGE_CRASH_SYSTEMD_SIGNAL_STR           SD_ID128_MAKE_STR(83,f8,4b,35,ee,26,4f,74,a3,89,6a,97,17,af,34,cb)
#define SD_MESSAGE_CRASH_PROCESS_SIGNAL               SD_ID128_MAKE(3a,73,a9,8b,af,5b,4b,19,99,29,e3,22,6c,0b,e7,83)
#define SD_MESSAGE_CRASH_PROCESS_SIGNAL_STR           SD_ID128_MAKE_STR(3a,73,a9,8b,af,5b,4b,19,99,29,e3,22,6c,0b,e7,83)
#define SD_MESSAGE_CRASH_WAITPID_FAILED               SD_ID128_MAKE(2e,d1,8d,4f,78,ca,47,f0,a9,bc,25,27,1c,26,ad,b4)
#define SD_MESSAGE_CRASH_WAITPID_FAILED_STR           SD_ID128_MAKE_STR(2e,d1,8d,4f,78,ca,47,f0,a9,bc,25,27,1c,26,ad,b4)
#define SD_MESSAGE_CRASH_COREDUMP_FAILED              SD_ID128_MAKE(56,b1,cd,96,f2,42,46,c5,b6,07,66,6f,da,95,23,56)
#define SD_MESSAGE_CRASH_COREDUMP_FAILED_STR          SD_ID128_MAKE_STR(56,b1,cd,96,f2,42,46,c5,b6,07,66,6f,da,95,23,56)
#define SD_MESSAGE_CRASH_COREDUMP_PID                 SD_ID128_MAKE(4a,c7,56,6d,4d,75,48,f4,98,1f,62,9a,28,f0,f8,29)
#define SD_MESSAGE_CRASH_COREDUMP_PID_STR             SD_ID128_MAKE_STR(4a,c7,56,6d,4d,75,48,f4,98,1f,62,9a,28,f0,f8,29)
#define SD_MESSAGE_CRASH_SHELL_FORK_FAILED            SD_ID128_MAKE(38,e8,b1,e0,39,ad,46,92,91,b1,8b,44,c5,53,a5,b7)
#define SD_MESSAGE_CRASH_SHELL_FORK_FAILED_STR        SD_ID128_MAKE_STR(38,e8,b1,e0,39,ad,46,92,91,b1,8b,44,c5,53,a5,b7)
#define SD_MESSAGE_CRASH_EXECLE_FAILED                SD_ID128_MAKE(87,27,29,b4,7d,be,47,3e,b7,68,cc,ec,d4,77,be,da)
#define SD_MESSAGE_CRASH_EXECLE_FAILED_STR            SD_ID128_MAKE_STR(87,27,29,b4,7d,be,47,3e,b7,68,cc,ec,d4,77,be,da)

#define SD_MESSAGE_SELINUX_FAILED                     SD_ID128_MAKE(65,8a,67,ad,c1,c9,40,b3,b3,31,6e,7e,86,28,83,4a)
#define SD_MESSAGE_SELINUX_FAILED_STR                 SD_ID128_MAKE_STR(65,8a,67,ad,c1,c9,40,b3,b3,31,6e,7e,86,28,83,4a)

#define SD_MESSAGE_BATTERY_LOW_WARNING                SD_ID128_MAKE(e6,f4,56,bd,92,00,4d,95,80,16,0b,22,07,55,51,86)
#define SD_MESSAGE_BATTERY_LOW_WARNING_STR            SD_ID128_MAKE_STR(e6,f4,56,bd,92,00,4d,95,80,16,0b,22,07,55,51,86)
#define SD_MESSAGE_BATTERY_LOW_POWEROFF               SD_ID128_MAKE(26,74,37,d3,3f,dd,41,09,9a,d7,62,21,cc,24,a3,35)
#define SD_MESSAGE_BATTERY_LOW_POWEROFF_STR           SD_ID128_MAKE_STR(26,74,37,d3,3f,dd,41,09,9a,d7,62,21,cc,24,a3,35)

#define SD_MESSAGE_CORE_MAINLOOP_FAILED               SD_ID128_MAKE(79,e0,5b,67,bc,45,45,d1,92,2f,e4,71,07,ee,60,c5)
#define SD_MESSAGE_CORE_MAINLOOP_FAILED_STR           SD_ID128_MAKE_STR(79,e0,5b,67,bc,45,45,d1,92,2f,e4,71,07,ee,60,c5)
#define SD_MESSAGE_CORE_NO_XDGDIR_PATH                SD_ID128_MAKE(db,b1,36,b1,0e,f4,45,7b,a4,7a,79,5d,62,f1,08,c9)
#define SD_MESSAGE_CORE_NO_XDGDIR_PATH_STR            SD_ID128_MAKE_STR(db,b1,36,b1,0e,f4,45,7b,a4,7a,79,5d,62,f1,08,c9)
#define SD_MESSAGE_CORE_CAPABILITY_BOUNDING_USER      SD_ID128_MAKE(ed,15,8c,2d,f8,88,4f,a5,84,ee,ad,2d,90,2c,10,32)
#define SD_MESSAGE_CORE_CAPABILITY_BOUNDING_USER_STR  SD_ID128_MAKE_STR(ed,15,8c,2d,f8,88,4f,a5,84,ee,ad,2d,90,2c,10,32)
#define SD_MESSAGE_CORE_CAPABILITY_BOUNDING           SD_ID128_MAKE(42,69,5b,50,0d,f0,48,29,8b,ee,37,15,9c,aa,9f,2e)
#define SD_MESSAGE_CORE_CAPABILITY_BOUNDING_STR       SD_ID128_MAKE_STR(42,69,5b,50,0d,f0,48,29,8b,ee,37,15,9c,aa,9f,2e)
#define SD_MESSAGE_CORE_DISABLE_PRIVILEGES            SD_ID128_MAKE(bf,c2,43,07,24,ab,44,49,97,35,b4,f9,4c,ca,92,95)
#define SD_MESSAGE_CORE_DISABLE_PRIVILEGES_STR        SD_ID128_MAKE_STR(bf,c2,43,07,24,ab,44,49,97,35,b4,f9,4c,ca,92,95)
#define SD_MESSAGE_CORE_START_TARGET_FAILED           SD_ID128_MAKE(59,28,8a,f5,23,be,43,a2,8d,49,4e,41,e2,6e,45,10)
#define SD_MESSAGE_CORE_START_TARGET_FAILED_STR       SD_ID128_MAKE_STR(59,28,8a,f5,23,be,43,a2,8d,49,4e,41,e2,6e,45,10)
#define SD_MESSAGE_CORE_ISOLATE_TARGET_FAILED         SD_ID128_MAKE(68,9b,4f,cc,97,b4,48,6e,a5,da,92,db,69,c9,e3,14)
#define SD_MESSAGE_CORE_ISOLATE_TARGET_FAILED_STR     SD_ID128_MAKE_STR(68,9b,4f,cc,97,b4,48,6e,a5,da,92,db,69,c9,e3,14)
#define SD_MESSAGE_CORE_FD_SET_FAILED                 SD_ID128_MAKE(5e,d8,36,f1,76,6f,4a,8a,9f,c5,da,45,aa,e2,3b,29)
#define SD_MESSAGE_CORE_FD_SET_FAILED_STR             SD_ID128_MAKE_STR(5e,d8,36,f1,76,6f,4a,8a,9f,c5,da,45,aa,e2,3b,29)
#define SD_MESSAGE_CORE_PID1_ENVIRONMENT              SD_ID128_MAKE(6a,40,fb,fb,d2,ba,4b,8d,b0,2f,b4,0c,9c,d0,90,d7)
#define SD_MESSAGE_CORE_PID1_ENVIRONMENT_STR          SD_ID128_MAKE_STR(6a,40,fb,fb,d2,ba,4b,8d,b0,2f,b4,0c,9c,d0,90,d7)
#define SD_MESSAGE_CORE_MANAGER_ALLOCATE              SD_ID128_MAKE(0e,54,47,09,84,ac,41,96,89,74,3d,95,7a,11,9e,2e)
#define SD_MESSAGE_CORE_MANAGER_ALLOCATE_STR          SD_ID128_MAKE_STR(0e,54,47,09,84,ac,41,96,89,74,3d,95,7a,11,9e,2e)

#define SD_MESSAGE_SMACK_FAILED_WRITE                 SD_ID128_MAKE(d6,7f,a9,f8,47,aa,4b,04,8a,2a,e3,35,35,33,1a,db)
#define SD_MESSAGE_SMACK_FAILED_WRITE_STR             SD_ID128_MAKE_STR(d6,7f,a9,f8,47,aa,4b,04,8a,2a,e3,35,35,33,1a,db)

#define SD_MESSAGE_SHUTDOWN_ERROR                     SD_ID128_MAKE(af,55,a6,f7,5b,54,44,31,b7,26,49,f3,6f,f6,d6,2c)
#define SD_MESSAGE_SHUTDOWN_ERROR_STR                 SD_ID128_MAKE_STR(af,55,a6,f7,5b,54,44,31,b7,26,49,f3,6f,f6,d6,2c)

#define SD_MESSAGE_VALGRIND_HELPER_FORK               SD_ID128_MAKE(d1,8e,03,39,ef,b2,4a,06,8d,9c,10,60,22,10,48,c2)
#define SD_MESSAGE_VALGRIND_HELPER_FORK_STR           SD_ID128_MAKE_STR(d1,8e,03,39,ef,b2,4a,06,8d,9c,10,60,22,10,48,c2)

/* The messages below are actually about jobs, not really about units, the macros are misleadingly named.
 * Moreover SD_MESSAGE_UNIT_FAILED is not actually about a failing unit but about a failed start job. A job
 * either finishes with SD_MESSAGE_UNIT_STARTED or with SD_MESSAGE_UNIT_FAILED hence. */
#define SD_MESSAGE_UNIT_STARTING                      SD_ID128_MAKE(7d,49,58,e8,42,da,4a,75,8f,6c,1c,dc,7b,36,dc,c5)
#define SD_MESSAGE_UNIT_STARTING_STR                  SD_ID128_MAKE_STR(7d,49,58,e8,42,da,4a,75,8f,6c,1c,dc,7b,36,dc,c5)
#define SD_MESSAGE_UNIT_STARTED                       SD_ID128_MAKE(39,f5,34,79,d3,a0,45,ac,8e,11,78,62,48,23,1f,bf)
#define SD_MESSAGE_UNIT_STARTED_STR                   SD_ID128_MAKE_STR(39,f5,34,79,d3,a0,45,ac,8e,11,78,62,48,23,1f,bf)
#define SD_MESSAGE_UNIT_FAILED                        SD_ID128_MAKE(be,02,cf,68,55,d2,42,8b,a4,0d,f7,e9,d0,22,f0,3d)
#define SD_MESSAGE_UNIT_FAILED_STR                    SD_ID128_MAKE_STR(be,02,cf,68,55,d2,42,8b,a4,0d,f7,e9,d0,22,f0,3d)
#define SD_MESSAGE_UNIT_STOPPING                      SD_ID128_MAKE(de,5b,42,6a,63,be,47,a7,b6,ac,3e,aa,c8,2e,2f,6f)
#define SD_MESSAGE_UNIT_STOPPING_STR                  SD_ID128_MAKE_STR(de,5b,42,6a,63,be,47,a7,b6,ac,3e,aa,c8,2e,2f,6f)
#define SD_MESSAGE_UNIT_STOPPED                       SD_ID128_MAKE(9d,1a,aa,27,d6,01,40,bd,96,36,54,38,aa,d2,02,86)
#define SD_MESSAGE_UNIT_STOPPED_STR                   SD_ID128_MAKE_STR(9d,1a,aa,27,d6,01,40,bd,96,36,54,38,aa,d2,02,86)
#define SD_MESSAGE_UNIT_RELOADING                     SD_ID128_MAKE(d3,4d,03,7f,ff,18,47,e6,ae,66,9a,37,0e,69,47,25)
#define SD_MESSAGE_UNIT_RELOADING_STR                 SD_ID128_MAKE_STR(d3,4d,03,7f,ff,18,47,e6,ae,66,9a,37,0e,69,47,25)
#define SD_MESSAGE_UNIT_RELOADED                      SD_ID128_MAKE(7b,05,eb,c6,68,38,42,22,ba,a8,88,11,79,cf,da,54)
#define SD_MESSAGE_UNIT_RELOADED_STR                  SD_ID128_MAKE_STR(7b,05,eb,c6,68,38,42,22,ba,a8,88,11,79,cf,da,54)

#define SD_MESSAGE_UNIT_RESTART_SCHEDULED             SD_ID128_MAKE(5e,b0,34,94,b6,58,48,70,a5,36,b3,37,29,08,09,b3)
#define SD_MESSAGE_UNIT_RESTART_SCHEDULED_STR         SD_ID128_MAKE_STR(5e,b0,34,94,b6,58,48,70,a5,36,b3,37,29,08,09,b3)

#define SD_MESSAGE_UNIT_RESOURCES                     SD_ID128_MAKE(ae,8f,7b,86,6b,03,47,b9,af,31,fe,1c,80,b1,27,c0)
#define SD_MESSAGE_UNIT_RESOURCES_STR                 SD_ID128_MAKE_STR(ae,8f,7b,86,6b,03,47,b9,af,31,fe,1c,80,b1,27,c0)

#define SD_MESSAGE_UNIT_SUCCESS                       SD_ID128_MAKE(7a,d2,d1,89,f7,e9,4e,70,a3,8c,78,13,54,91,24,48)
#define SD_MESSAGE_UNIT_SUCCESS_STR                   SD_ID128_MAKE_STR(7a,d2,d1,89,f7,e9,4e,70,a3,8c,78,13,54,91,24,48)
#define SD_MESSAGE_UNIT_SKIPPED                       SD_ID128_MAKE(0e,42,84,a0,ca,ca,4b,fc,81,c0,bb,67,86,97,26,73)
#define SD_MESSAGE_UNIT_SKIPPED_STR                   SD_ID128_MAKE_STR(0e,42,84,a0,ca,ca,4b,fc,81,c0,bb,67,86,97,26,73)
#define SD_MESSAGE_UNIT_FAILURE_RESULT                SD_ID128_MAKE(d9,b3,73,ed,55,a6,4f,eb,82,42,e0,2d,be,79,a4,9c)
#define SD_MESSAGE_UNIT_FAILURE_RESULT_STR            SD_ID128_MAKE_STR(d9,b3,73,ed,55,a6,4f,eb,82,42,e0,2d,be,79,a4,9c)

#define SD_MESSAGE_SPAWN_FAILED                       SD_ID128_MAKE(64,12,57,65,1c,1b,4e,c9,a8,62,4d,7a,40,a9,e1,e7)
#define SD_MESSAGE_SPAWN_FAILED_STR                   SD_ID128_MAKE_STR(64,12,57,65,1c,1b,4e,c9,a8,62,4d,7a,40,a9,e1,e7)

#define SD_MESSAGE_UNIT_PROCESS_EXIT                  SD_ID128_MAKE(98,e3,22,20,3f,7a,4e,d2,90,d0,9f,e0,3c,09,fe,15)
#define SD_MESSAGE_UNIT_PROCESS_EXIT_STR              SD_ID128_MAKE_STR(98,e3,22,20,3f,7a,4e,d2,90,d0,9f,e0,3c,09,fe,15)

#define SD_MESSAGE_FORWARD_SYSLOG_MISSED              SD_ID128_MAKE(00,27,22,9c,a0,64,41,81,a7,6c,4e,92,45,8a,fa,2e)
#define SD_MESSAGE_FORWARD_SYSLOG_MISSED_STR          SD_ID128_MAKE_STR(00,27,22,9c,a0,64,41,81,a7,6c,4e,92,45,8a,fa,2e)

#define SD_MESSAGE_OVERMOUNTING                       SD_ID128_MAKE(1d,ee,03,69,c7,fc,47,36,b7,09,9b,38,ec,b4,6e,e7)
#define SD_MESSAGE_OVERMOUNTING_STR                   SD_ID128_MAKE_STR(1d,ee,03,69,c7,fc,47,36,b7,09,9b,38,ec,b4,6e,e7)
#define SD_MESSAGE_NON_CANONICAL_MOUNT                SD_ID128_MAKE(1e,da,bb,4e,da,2a,49,c1,9b,c0,20,6f,24,b4,38,89)
#define SD_MESSAGE_NON_CANONICAL_MOUNT_STR            SD_ID128_MAKE_STR(1e,da,bb,4e,da,2a,49,c1,9b,c0,20,6f,24,b4,38,89)

#define SD_MESSAGE_UNIT_OOMD_KILL                     SD_ID128_MAKE(d9,89,61,1b,15,e4,4c,9d,bf,31,e3,c8,12,56,e4,ed)
#define SD_MESSAGE_UNIT_OOMD_KILL_STR                 SD_ID128_MAKE_STR(d9,89,61,1b,15,e4,4c,9d,bf,31,e3,c8,12,56,e4,ed)

#define SD_MESSAGE_UNIT_OUT_OF_MEMORY                 SD_ID128_MAKE(fe,6f,aa,94,e7,77,46,63,a0,da,52,71,78,91,d8,ef)
#define SD_MESSAGE_UNIT_OUT_OF_MEMORY_STR             SD_ID128_MAKE_STR(fe,6f,aa,94,e7,77,46,63,a0,da,52,71,78,91,d8,ef)

#define SD_MESSAGE_LID_OPENED                         SD_ID128_MAKE(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,6f)
#define SD_MESSAGE_LID_OPENED_STR                     SD_ID128_MAKE_STR(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,6f)
#define SD_MESSAGE_LID_CLOSED                         SD_ID128_MAKE(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,70)
#define SD_MESSAGE_LID_CLOSED_STR                     SD_ID128_MAKE_STR(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,70)
#define SD_MESSAGE_SYSTEM_DOCKED                      SD_ID128_MAKE(f5,f4,16,b8,62,07,4b,28,92,7a,48,c3,ba,7d,51,ff)
#define SD_MESSAGE_SYSTEM_DOCKED_STR                  SD_ID128_MAKE_STR(f5,f4,16,b8,62,07,4b,28,92,7a,48,c3,ba,7d,51,ff)
#define SD_MESSAGE_SYSTEM_UNDOCKED                    SD_ID128_MAKE(51,e1,71,bd,58,52,48,56,81,10,14,4c,51,7c,ca,53)
#define SD_MESSAGE_SYSTEM_UNDOCKED_STR                SD_ID128_MAKE_STR(51,e1,71,bd,58,52,48,56,81,10,14,4c,51,7c,ca,53)
#define SD_MESSAGE_POWER_KEY                          SD_ID128_MAKE(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,71)
#define SD_MESSAGE_POWER_KEY_STR                      SD_ID128_MAKE_STR(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,71)
#define SD_MESSAGE_POWER_KEY_LONG_PRESS               SD_ID128_MAKE(3e,01,17,10,1e,b2,43,c1,b9,a5,0d,b3,49,4a,b1,0b)
#define SD_MESSAGE_POWER_KEY_LONG_PRESS_STR           SD_ID128_MAKE_STR(3e,01,17,10,1e,b2,43,c1,b9,a5,0d,b3,49,4a,b1,0b)
#define SD_MESSAGE_SECURE_ATTENTION_KEY_PRESS         SD_ID128_MAKE(b2,bc,ba,f5,ed,f9,48,e0,93,ce,50,bb,ea,0e,81,ec)
#define SD_MESSAGE_SECURE_ATTENTION_KEY_PRESS_STR     SD_ID128_MAKE_STR(b2,bc,ba,f5,ed,f9,48,e0,93,ce,50,bb,ea,0e,81,ec)
#define SD_MESSAGE_REBOOT_KEY                         SD_ID128_MAKE(9f,a9,d2,c0,12,13,4e,c3,85,45,1f,fe,31,6f,97,d0)
#define SD_MESSAGE_REBOOT_KEY_STR                     SD_ID128_MAKE_STR(9f,a9,d2,c0,12,13,4e,c3,85,45,1f,fe,31,6f,97,d0)
#define SD_MESSAGE_REBOOT_KEY_LONG_PRESS              SD_ID128_MAKE(f1,c5,9a,58,c9,d9,43,66,89,65,c3,37,ca,ec,59,75)
#define SD_MESSAGE_REBOOT_KEY_LONG_PRESS_STR          SD_ID128_MAKE_STR(f1,c5,9a,58,c9,d9,43,66,89,65,c3,37,ca,ec,59,75)
#define SD_MESSAGE_SUSPEND_KEY                        SD_ID128_MAKE(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,72)
#define SD_MESSAGE_SUSPEND_KEY_STR                    SD_ID128_MAKE_STR(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,72)
#define SD_MESSAGE_SUSPEND_KEY_LONG_PRESS             SD_ID128_MAKE(bf,da,f6,d3,12,ab,40,07,bc,1f,e4,0a,15,df,78,e8)
#define SD_MESSAGE_SUSPEND_KEY_LONG_PRESS_STR         SD_ID128_MAKE_STR(bf,da,f6,d3,12,ab,40,07,bc,1f,e4,0a,15,df,78,e8)
#define SD_MESSAGE_HIBERNATE_KEY                      SD_ID128_MAKE(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,73)
#define SD_MESSAGE_HIBERNATE_KEY_STR                  SD_ID128_MAKE_STR(b7,2e,a4,a2,88,15,45,a0,b5,0e,20,0e,55,b9,b0,73)
#define SD_MESSAGE_HIBERNATE_KEY_LONG_PRESS           SD_ID128_MAKE(16,78,36,df,6f,7f,42,8e,98,14,72,27,b2,dc,89,45)
#define SD_MESSAGE_HIBERNATE_KEY_LONG_PRESS_STR       SD_ID128_MAKE_STR(16,78,36,df,6f,7f,42,8e,98,14,72,27,b2,dc,89,45)

#define SD_MESSAGE_INVALID_CONFIGURATION              SD_ID128_MAKE(c7,72,d2,4e,9a,88,4c,be,b9,ea,12,62,5c,30,6c,01)
#define SD_MESSAGE_INVALID_CONFIGURATION_STR          SD_ID128_MAKE_STR(c7,72,d2,4e,9a,88,4c,be,b9,ea,12,62,5c,30,6c,01)

#define SD_MESSAGE_DNSSEC_FAILURE                     SD_ID128_MAKE(16,75,d7,f1,72,17,40,98,b1,10,8b,f8,c7,dc,8f,5d)
#define SD_MESSAGE_DNSSEC_FAILURE_STR                 SD_ID128_MAKE_STR(16,75,d7,f1,72,17,40,98,b1,10,8b,f8,c7,dc,8f,5d)
#define SD_MESSAGE_DNSSEC_TRUST_ANCHOR_REVOKED        SD_ID128_MAKE(4d,44,08,cf,d0,d1,44,85,91,84,d1,e6,5d,7c,8a,65)
#define SD_MESSAGE_DNSSEC_TRUST_ANCHOR_REVOKED_STR    SD_ID128_MAKE_STR(4d,44,08,cf,d0,d1,44,85,91,84,d1,e6,5d,7c,8a,65)
#define SD_MESSAGE_DNSSEC_DOWNGRADE                   SD_ID128_MAKE(36,db,2d,fa,5a,90,45,e1,bd,4a,f5,f9,3e,1c,f0,57)
#define SD_MESSAGE_DNSSEC_DOWNGRADE_STR               SD_ID128_MAKE_STR(36,db,2d,fa,5a,90,45,e1,bd,4a,f5,f9,3e,1c,f0,57)

#define SD_MESSAGE_UNSAFE_USER_NAME                   SD_ID128_MAKE(b6,1f,da,c6,12,e9,4b,91,82,28,5b,99,88,43,06,1f)
#define SD_MESSAGE_UNSAFE_USER_NAME_STR               SD_ID128_MAKE_STR(b6,1f,da,c6,12,e9,4b,91,82,28,5b,99,88,43,06,1f)

#define SD_MESSAGE_MOUNT_POINT_PATH_NOT_SUITABLE      SD_ID128_MAKE(1b,3b,b9,40,37,f0,4b,bf,81,02,8e,13,5a,12,d2,93)
#define SD_MESSAGE_MOUNT_POINT_PATH_NOT_SUITABLE_STR  SD_ID128_MAKE_STR(1b,3b,b9,40,37,f0,4b,bf,81,02,8e,13,5a,12,d2,93)
#define SD_MESSAGE_DEVICE_PATH_NOT_SUITABLE           SD_ID128_MAKE(01,01,90,13,8f,49,4e,29,a0,ef,66,69,74,95,31,aa)
#define SD_MESSAGE_DEVICE_PATH_NOT_SUITABLE_STR       SD_ID128_MAKE_STR(01,01,90,13,8f,49,4e,29,a0,ef,66,69,74,95,31,aa)

#define SD_MESSAGE_NOBODY_USER_UNSUITABLE             SD_ID128_MAKE(b4,80,32,5f,9c,39,4a,7b,80,2c,23,1e,51,a2,75,2c)
#define SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR         SD_ID128_MAKE_STR(b4,80,32,5f,9c,39,4a,7b,80,2c,23,1e,51,a2,75,2c)

#define SD_MESSAGE_SYSTEMD_UDEV_SETTLE_DEPRECATED     SD_ID128_MAKE(1c,04,54,c1,bd,22,41,e0,ac,6f,ef,b4,bc,63,14,33)
#define SD_MESSAGE_SYSTEMD_UDEV_SETTLE_DEPRECATED_STR SD_ID128_MAKE_STR(1c,04,54,c1,bd,22,41,e0,ac,6f,ef,b4,bc,63,14,33)

#define SD_MESSAGE_TIME_SYNC                          SD_ID128_MAKE(7c,8a,41,f3,7b,76,49,41,a0,e1,78,0b,1b,e2,f0,37)
#define SD_MESSAGE_TIME_SYNC_STR                      SD_ID128_MAKE_STR(7c,8a,41,f3,7b,76,49,41,a0,e1,78,0b,1b,e2,f0,37)

#define SD_MESSAGE_TIME_BUMP                          SD_ID128_MAKE(7d,b7,3c,8a,f0,d9,4e,eb,82,2a,e0,43,23,fe,6a,b6)
#define SD_MESSAGE_TIME_BUMP_STR                      SD_ID128_MAKE_STR(7d,b7,3c,8a,f0,d9,4e,eb,82,2a,e0,43,23,fe,6a,b6)

#define SD_MESSAGE_WATCHDOG_OPENED                    SD_ID128_MAKE(21,66,8d,bd,3d,7a,4a,32,a2,67,6d,53,da,da,b0,22)
#define SD_MESSAGE_WATCHDOG_OPENED_STR                SD_ID128_MAKE_STR(21,66,8d,bd,3d,7a,4a,32,a2,67,6d,53,da,da,b0,22)

#define SD_MESSAGE_WATCHDOG_OPEN_FAILED               SD_ID128_MAKE(37,5a,c1,51,ef,9d,4d,e3,90,68,b3,ef,bf,ed,0c,ee)
#define SD_MESSAGE_WATCHDOG_OPEN_FAILED_STR           SD_ID128_MAKE_STR(37,5a,c1,51,ef,9d,4d,e3,90,68,b3,ef,bf,ed,0c,ee)

#define SD_MESSAGE_WATCHDOG_PING_FAILED               SD_ID128_MAKE(87,39,78,9e,ca,06,43,25,af,15,a8,ed,0e,cf,c5,56)
#define SD_MESSAGE_WATCHDOG_PING_FAILED_STR           SD_ID128_MAKE_STR(87,39,78,9e,ca,06,43,25,af,15,a8,ed,0e,cf,c5,56)

#define SD_MESSAGE_SHUTDOWN_SCHEDULED                 SD_ID128_MAKE(9e,70,66,27,9d,c8,40,3d,a7,9c,e4,b1,a6,90,64,b2)
#define SD_MESSAGE_SHUTDOWN_SCHEDULED_STR             SD_ID128_MAKE_STR(9e,70,66,27,9d,c8,40,3d,a7,9c,e4,b1,a6,90,64,b2)

#define SD_MESSAGE_SHUTDOWN_CANCELED                  SD_ID128_MAKE(24,9f,6f,b9,e6,e2,42,8c,96,f3,f0,87,56,81,ff,a3)
#define SD_MESSAGE_SHUTDOWN_CANCELED_STR              SD_ID128_MAKE_STR(24,9f,6f,b9,e6,e2,42,8c,96,f3,f0,87,56,81,ff,a3)

#define SD_MESSAGE_TPM_PCR_EXTEND                     SD_ID128_MAKE(3f,7d,5e,f3,e5,4f,43,02,b4,f0,b1,43,bb,27,0c,ab)
#define SD_MESSAGE_TPM_PCR_EXTEND_STR                 SD_ID128_MAKE_STR(3f,7d,5e,f3,e5,4f,43,02,b4,f0,b1,43,bb,27,0c,ab)
#define SD_MESSAGE_TPM_NVPCR_EXTEND                   SD_ID128_MAKE(4c,2e,46,d2,66,a7,47,c6,ac,14,60,aa,54,48,4f,a7)
#define SD_MESSAGE_TPM_NVPCR_EXTEND_STR               SD_ID128_MAKE_STR(4c,2e,46,d2,66,a7,47,c6,ac,14,60,aa,54,48,4f,a7)

#define SD_MESSAGE_MEMORY_TRIM                        SD_ID128_MAKE(f9,b0,be,46,5a,d5,40,d0,85,0a,d3,21,72,d5,7c,21)
#define SD_MESSAGE_MEMORY_TRIM_STR                    SD_ID128_MAKE_STR(f9,b0,be,46,5a,d5,40,d0,85,0a,d3,21,72,d5,7c,21)

#define SD_MESSAGE_SYSV_GENERATOR_DEPRECATED          SD_ID128_MAKE(a8,fa,8d,ac,db,1d,44,3e,95,03,b8,be,36,7a,6a,db)
#define SD_MESSAGE_SYSV_GENERATOR_DEPRECATED_STR      SD_ID128_MAKE_STR(a8,fa,8d,ac,db,1d,44,3e,95,03,b8,be,36,7a,6a,db)

#define SD_MESSAGE_PORTABLE_ATTACHED                  SD_ID128_MAKE(18,7c,62,eb,1e,7f,46,3b,b5,30,39,4f,52,cb,09,0f)
#define SD_MESSAGE_PORTABLE_ATTACHED_STR              SD_ID128_MAKE_STR(18,7c,62,eb,1e,7f,46,3b,b5,30,39,4f,52,cb,09,0f)
#define SD_MESSAGE_PORTABLE_DETACHED                  SD_ID128_MAKE(76,c5,c7,54,d6,28,49,0d,8e,cb,a4,c9,d0,42,11,2b)
#define SD_MESSAGE_PORTABLE_DETACHED_STR              SD_ID128_MAKE_STR(76,c5,c7,54,d6,28,49,0d,8e,cb,a4,c9,d0,42,11,2b)

#define SD_MESSAGE_SRK_ENROLLMENT_NEEDS_AUTHORIZATION     SD_ID128_MAKE(ad,70,89,f9,28,ac,4f,7e,a0,0c,07,45,7d,47,ba,8a)
#define SD_MESSAGE_SRK_ENROLLMENT_NEEDS_AUTHORIZATION_STR SD_ID128_MAKE_STR(ad,70,89,f9,28,ac,4f,7e,a0,0c,07,45,7d,47,ba,8a)
#define SD_MESSAGE_TPM2_CLEAR_REQUESTED               SD_ID128_MAKE(43,81,88,86,1e,0b,42,7a,9d,63,8a,90,48,7a,0c,a6)
#define SD_MESSAGE_TPM2_CLEAR_REQUESTED_STR           SD_ID128_MAKE_STR(43,81,88,86,1e,0b,42,7a,9d,63,8a,90,48,7a,0c,a6)

#define SD_MESSAGE_SYSCTL_CHANGED                     SD_ID128_MAKE(9c,f5,6b,8b,af,95,46,cf,94,78,78,3a,8d,e4,21,13)
#define SD_MESSAGE_SYSCTL_CHANGED_STR                 SD_ID128_MAKE_STR(9c,f5,6b,8b,af,95,46,cf,94,78,78,3a,8d,e4,21,13)

#define SD_MESSAGE_UNIT_ORDERING_CYCLE                SD_ID128_MAKE(f2,7a,3f,94,40,6a,47,83,b9,46,a9,bc,84,9e,94,52)
#define SD_MESSAGE_UNIT_ORDERING_CYCLE_STR            SD_ID128_MAKE_STR(f2,7a,3f,94,40,6a,47,83,b9,46,a9,bc,84,9e,94,52)

#define SD_MESSAGE_DELETING_JOB_BECAUSE_ORDERING_CYCLE     SD_ID128_MAKE(50,84,36,75,42,f7,47,2d,bc,6a,94,12,5d,5d,eb,ce)
#define SD_MESSAGE_DELETING_JOB_BECAUSE_ORDERING_CYCLE_STR SD_ID128_MAKE_STR(50,84,36,75,42,f7,47,2d,bc,6a,94,12,5d,5d,eb,ce)

#define SD_MESSAGE_CANT_BREAK_ORDERING_CYCLE          SD_ID128_MAKE(b3,11,2d,da,d1,90,45,53,8c,76,68,5b,a5,91,8a,80)
#define SD_MESSAGE_CANT_BREAK_ORDERING_CYCLE_STR      SD_ID128_MAKE_STR(b3,11,2d,da,d1,90,45,53,8c,76,68,5b,a5,91,8a,80)

#define SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED            SD_ID128_MAKE(34,05,20,5d,36,8e,49,fe,b5,ab,39,25,fe,e1,38,74)
#define SD_MESSAGE_SYSTEM_ACCOUNT_REQUIRED_STR        SD_ID128_MAKE_STR(34,05,20,5d,36,8e,49,fe,b5,ab,39,25,fe,e1,38,74)

_SD_END_DECLARATIONS;

#endif
