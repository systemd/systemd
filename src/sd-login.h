/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdloginhfoo
#define foosdloginhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>

/*
 * A few points:
 *
 * Instead of returning an empty string array or empty uid array, we
 * may return NULL.
 *
 * Free the data we return with libc free().
 *
 * We return error codes as negative errno, kernel-style.
 *
 * These functions access data in /proc, /sys/fs/cgroup and /run. All
 * of these are virtual file systems, hence the accesses are
 * relatively cheap.
 */

/* Get session from PID. Note that 'shared' processes of a user are
 * not attached to a session, but only attached to a user. This will
 * return an error for system processes and 'shared' processes of a
 * user. */
int sd_pid_get_session(pid_t pid, char **session);

/* Get UID of the owner of the session of the PID (or in case the
 * process is a 'shared' user process the UID of that user is
 * returned). This will not return the UID of the process, but rather
 * the UID of the owner of the cgroup the process is in. This will
 * return an error for system processes. */
int sd_pid_get_owner_uid(pid_t pid, uid_t *uid);

/* Get state from uid. Possible states: offline, lingering, online, active */
int sd_uid_get_state(uid_t uid, char**state);

/* Return 1 if uid has session on seat. If require_active is true will
 * look for active sessions only. */
int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat);

/* Return sessions of user. If require_active is true will look
 * for active sessions only. */
int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions);

/* Return seats of user is on. If require_active is true will look for
 * active seats only.  */
int sd_uid_get_seats(uid_t uid, int require_active, char ***seats);

/* Return 1 if the session is a active */
int sd_session_is_active(const char *session);

/* Determine user id of session */
int sd_session_get_uid(const char *session, uid_t *uid);

/* Determine seat of session */
int sd_session_get_seat(const char *session, char **seat);

/* Return active session and user of seat */
int sd_seat_get_active(const char *seat, char **session, uid_t *uid);

/* Return sessions and users on seat */
int sd_seat_get_sessions(const char *seat, char ***sessions, uid_t **uid, unsigned *n_uids);

/* Get all seats */
int sd_get_seats(char ***seats);

/* Get all sessions */
int sd_get_sessions(char ***sessions);

/* Get all logged in users */
int sd_get_uids(uid_t **users);

/* Monitor object */
typedef struct sd_login_monitor sd_login_monitor;

/* Create a new monitor. Category must be NULL, "seat", "session",
 * "uid" to get monitor events for the specific category (or all). */
int sd_login_monitor_new(const char *category, sd_login_monitor** ret);

/* Destroys the passed monitor. Returns NULL. */
sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m);

/* Flushes the monitor */
int sd_login_monitor_flush(sd_login_monitor *m);

/* Get FD from monitor */
int sd_login_monitor_get_fd(sd_login_monitor *m);

#endif
