/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdloginhfoo
#define foosdloginhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <sys/types.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A few points:
 *
 * Instead of returning an empty string array or empty uid array, we
 * may return NULL.
 *
 * Free the data the library returns with libc free(). String arrays
 * are NULL terminated and you need to free the array itself in
 * addition to the strings contained.
 *
 * We return error codes as negative errno, kernel-style. 0 or
 * positive on success.
 *
 * These functions access data in /proc, /sys/fs/cgroup and /run. All
 * of these are virtual file systems, hence the accesses are
 * relatively cheap.
 *
 * See sd-login(3) for more information.
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

/* Get systemd unit (i.e. service) name from PID, for system
 * services. This will return an error for non-service processes. */
int sd_pid_get_unit(pid_t pid, char **unit);

/* Get systemd unit (i.e. service) name from PID, for user
 * services. This will return an error for non-user-service
 * processes. */
int sd_pid_get_user_unit(pid_t pid, char **unit);

/* Get machine name from PID, for processes assigned to VM or
 * container. This will return an error for non-service processes. */
int sd_pid_get_machine_name(pid_t pid, char **name);

/* Get state from uid. Possible states: offline, lingering, online, active, closing */
int sd_uid_get_state(uid_t uid, char**state);

/* Return 1 if uid has session on seat. If require_active is true will
 * look for active sessions only. */
int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat);

/* Return sessions of user. If require_active is true will look for
 * active sessions only. Returns number of sessions as return
 * value. If sessions is NULL will just return number of sessions. */
int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions);

/* Return seats of user is on. If require_active is true will look for
 * active seats only.  Returns number of seats. If seats is NULL will
 * just return number of seats.*/
int sd_uid_get_seats(uid_t uid, int require_active, char ***seats);

/* Return 1 if the session is a active. */
int sd_session_is_active(const char *session);

/* Get state from session. Possible states: online, active, closing
 * (This function is a more generic version of
 * sd_session_is_active().) */
int sd_session_get_state(const char *sessio, char **state);

/* Determine user id of session */
int sd_session_get_uid(const char *session, uid_t *uid);

/* Determine seat of session */
int sd_session_get_seat(const char *session, char **seat);

/* Determine the (PAM) service name this session was registered by. */
int sd_session_get_service(const char *session, char **service);

/* Determine the type of this session, i.e. one of "tty", "x11" or "unspecified". */
int sd_session_get_type(const char *session, char **type);

/* Determine the class of this session, i.e. one of "user", "greeter" or "lock-screen". */
int sd_session_get_class(const char *session, char **clazz);

/* Determine the X11 display of this session. */
int sd_session_get_display(const char *session, char **display);

/* Determine the TTY of this session. */
int sd_session_get_tty(const char *session, char **display);

/* Return active session and user of seat */
int sd_seat_get_active(const char *seat, char **session, uid_t *uid);

/* Return sessions and users on seat. Returns number of sessions as
 * return value. If sessions is NULL returns only the number of
 * sessions. */
int sd_seat_get_sessions(const char *seat, char ***sessions, uid_t **uid, unsigned *n_uids);

/* Return whether the seat is multi-session capable */
int sd_seat_can_multi_session(const char *seat);

/* Return whether the seat is TTY capable, i.e. suitable for showing console UIs */
int sd_seat_can_tty(const char *seat);

/* Return whether the seat is graphics capable, i.e. suitable for showing graphical UIs */
int sd_seat_can_graphical(const char *seat);

/* Get all seats, store in *seats. Returns the number of seats. If
 * seats is NULL only returns number of seats. */
int sd_get_seats(char ***seats);

/* Get all sessions, store in *sessions. Returns the number of
 * sessions. If sessions is NULL only returns number of sessions. */
int sd_get_sessions(char ***sessions);

/* Get all logged in users, store in *users. Returns the number of
 * users. If users is NULL only returns the number of users. */
int sd_get_uids(uid_t **users);

/* Get all running virtual machines/containers */
int sd_get_machine_names(char ***machines);

/* Monitor object */
typedef struct sd_login_monitor sd_login_monitor;

/* Create a new monitor. Category must be NULL, "seat", "session",
 * "uid", "machine" to get monitor events for the specific category
 * (or all). */
int sd_login_monitor_new(const char *category, sd_login_monitor** ret);

/* Destroys the passed monitor. Returns NULL. */
sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m);

/* Flushes the monitor */
int sd_login_monitor_flush(sd_login_monitor *m);

/* Get FD from monitor */
int sd_login_monitor_get_fd(sd_login_monitor *m);

/* Get poll() mask to monitor */
int sd_login_monitor_get_events(sd_login_monitor *m);

/* Get timeout for poll(), as usec value relative to CLOCK_MONOTONIC's epoch */
int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *timeout_usec);

#ifdef __cplusplus
}
#endif

#endif
