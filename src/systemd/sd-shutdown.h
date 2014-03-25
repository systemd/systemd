/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdshutdownhfoo
#define foosdshutdownhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/* Interface for scheduling and cancelling timed shutdowns. */

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _sd_packed_
#  define _sd_packed_ __attribute__((packed))
#endif

typedef enum sd_shutdown_mode {
        SD_SHUTDOWN_NONE = 0,
        SD_SHUTDOWN_REBOOT = 'r',
        SD_SHUTDOWN_POWEROFF = 'P',
        SD_SHUTDOWN_HALT = 'H',
        SD_SHUTDOWN_KEXEC = 'K'
} sd_shutdown_mode_t;

/* Calculate the size of the message as "offsetof(struct
 * sd_shutdown_command, wall_message) +
 * strlen(command.wall_message)" */
struct sd_shutdown_command {
        /* Microseconds after the epoch 1970 UTC */
        uint64_t usec;

        /* H, P, r, i.e. the switches usually passed to
         * /usr/bin/shutdown to select whether to halt, power-off or
         * reboot the machine */
        sd_shutdown_mode_t mode:8;

        /* If non-zero, don't actually shut down, just pretend */
        unsigned dry_run:1;

        /* If non-zero, send our wall message */
        unsigned warn_wall:1;

        /* The wall message to send around. Leave empty for the
         * default wall message */
        char wall_message[];
} _sd_packed_;

/* The scheme is very simple:
 *
 * To schedule a shutdown, simply fill in and send a single
 * AF_UNIX/SOCK_DGRAM datagram with the structure above suffixed with
 * the wall message to the socket /run/systemd/shutdownd (leave an
 * empty wall message for the default shutdown message). To calculate
 * the size of the message, use "offsetof(struct sd_shutdown_command,
 * wall_message) + strlen(command.wall_message)".
 *
 * To cancel a shutdown, do the same, but send a fully zeroed-out
 * structure.
 *
 * To be notified about scheduled shutdowns, create an inotify watch
 * on /run/shutdown/. Whenever a file called "scheduled" appears, a
 * shutdown is scheduled. If it is removed, it is canceled. If it is
 * replaced, the scheduled shutdown has been changed. The file contains
 * a simple, environment-like block that contains information about
 * the scheduled shutdown:
 *
 * USEC=
 * encodes the time for the shutdown in usecs since the epoch UTC,
 * formatted as a numeric string.
 *
 * WARN_WALL=
 * is 1 if a wall message shall be sent
 *
 * DRY_RUN=
 * is 1 if a dry-run shutdown is scheduled
 *
 * MODE=
 * is the shutdown mode, one of "poweroff", "reboot", "halt", "kexec"
 *
 * WALL_MESSAGE=
 * is the wall message to use, with all special characters escaped in C-style.
 *
 * Note that some fields might be missing if they do not apply.
 *
 * Note that the file is first written to a temporary file and then
 * renamed, in order to provide atomic properties for readers: if the
 * file exists under the name "scheduled", it is guaranteed to be fully
 * written. A reader should ignore all files in that directory by any
 * other name.
 *
 * Scheduled shutdowns are only accepted from privileged processes,
 * but anyone may watch the directory and the file in it.
 */

#ifdef __cplusplus
}
#endif

#endif
