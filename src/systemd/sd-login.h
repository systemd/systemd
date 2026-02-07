/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdloginhfoo
#define foosdloginhfoo

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

/*
 * A few points:
 *
 * Instead of returning an empty string array or empty uid array, we
 * may return NULL.
 *
 * Free the data the library returns with libc free(). String arrays
 * are NULL terminated, and you need to free the array itself, in
 * addition to the strings contained.
 *
 * We return error codes as negative errno, kernel-style. On success, we
 * return 0 or positive.
 *
 * These functions access data in /proc, /sys/fs/cgroup, and /run. All
 * of these are virtual file systems; therefore, accesses are
 * relatively cheap.
 *
 * See sd-login(3) for more information.
 */

_SD_BEGIN_DECLARATIONS;

/* Get session from PID. Note that 'shared' processes of a user are
 * not attached to a session, but only attached to a user. This will
 * return an error for system processes and 'shared' processes of a
 * user. */
int sd_pid_get_session(pid_t pid, char **ret_session);

/* Get UID of the owner of the session of the PID (or in case the
 * process is a 'shared' user process, the UID of that user is
 * returned). This will not return the UID of the process, but rather
 * the UID of the owner of the cgroup that the process is in. This will
 * return an error for system processes. */
int sd_pid_get_owner_uid(pid_t pid, uid_t *ret_uid);

/* Get systemd non-slice unit (i.e. service) name from PID, for system
 * services. This will return an error for non-service processes. */
int sd_pid_get_unit(pid_t pid, char **ret_unit);

/* Get systemd non-slice unit (i.e. service) name from PID, for user
 * services. This will return an error for non-user-service
 * processes. */
int sd_pid_get_user_unit(pid_t pid, char **ret_unit);

/* Get slice name from PID. */
int sd_pid_get_slice(pid_t pid, char **ret_slice);

/* Get user slice name from PID. */
int sd_pid_get_user_slice(pid_t pid, char **ret_slice);

/* Get machine name from PID, for processes assigned to a VM or
 * container. This will return an error for non-machine processes. */
int sd_pid_get_machine_name(pid_t pid, char **ret_machine);

/* Get the control group from a PID, relative to the root of the
 * hierarchy. */
int sd_pid_get_cgroup(pid_t pid, char **ret_cgroup);

/* Equivalent to the corresponding sd_pid_get* functions, but take a
 * PIDFD instead of a PID, to ensure there can be no possible PID
 * recycle issues before/after the calls. */
int sd_pidfd_get_session(int pidfd, char **ret_session);
int sd_pidfd_get_owner_uid(int pidfd, uid_t *ret_uid);
int sd_pidfd_get_unit(int pidfd, char **ret_unit);
int sd_pidfd_get_user_unit(int pidfd, char **ret_unit);
int sd_pidfd_get_slice(int pidfd, char **ret_slice);
int sd_pidfd_get_user_slice(int pidfd, char **ret_slice);
int sd_pidfd_get_machine_name(int pidfd, char **ret_machine);
int sd_pidfd_get_cgroup(int pidfd, char **ret_cgroup);

/* Similar to sd_pid_get_session(), but retrieves data about the peer
 * of a connected AF_UNIX socket */
int sd_peer_get_session(int fd, char **ret_session);

/* Similar to sd_pid_get_owner_uid(), but retrieves data about the peer of
 * a connected AF_UNIX socket */
int sd_peer_get_owner_uid(int fd, uid_t *ret_uid);

/* Similar to sd_pid_get_unit(), but retrieves data about the peer of
 * a connected AF_UNIX socket */
int sd_peer_get_unit(int fd, char **ret_unit);

/* Similar to sd_pid_get_user_unit(), but retrieves data about the peer of
 * a connected AF_UNIX socket */
int sd_peer_get_user_unit(int fd, char **ret_unit);

/* Similar to sd_pid_get_slice(), but retrieves data about the peer of
 * a connected AF_UNIX socket */
int sd_peer_get_slice(int fd, char **ret_slice);

/* Similar to sd_pid_get_user_slice(), but retrieves data about the peer of
 * a connected AF_UNIX socket */
int sd_peer_get_user_slice(int fd, char **ret_slice);

/* Similar to sd_pid_get_machine_name(), but retrieves data about the
 * peer of a connected AF_UNIX socket */
int sd_peer_get_machine_name(int fd, char **ret_machine);

/* Similar to sd_pid_get_cgroup(), but retrieves data about the peer
 * of a connected AF_UNIX socket. */
int sd_peer_get_cgroup(int fd, char **ret_cgroup);

/* Get state from UID. Possible states: offline, lingering, online, active, closing */
int sd_uid_get_state(uid_t uid, char **ret_state);

/* Return primary session of user, if there is any */
int sd_uid_get_display(uid_t uid, char **ret_display);

/* Determine the login time of user */
int sd_uid_get_login_time(uid_t uid, uint64_t *ret_usec);

/* Return 1 if UID has session on seat. If require_active is true, this will
 * look for active sessions only. */
int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat);

/* Return sessions of user. If require_active is true, this will look for
 * active sessions only. Returns the number of sessions.
 * If sessions is NULL, this will just return the number of sessions. */
int sd_uid_get_sessions(uid_t uid, int require_active, char ***ret_sessions);

/* Return seats of user is on. If require_active is true, this will look for
 * active seats only. Returns the number of seats.
 * If seats is NULL, this will just return the number of seats. */
int sd_uid_get_seats(uid_t uid, int require_active, char ***ret_seats);

/* Return 1 if the session is active. */
int sd_session_is_active(const char *session);

/* Return 1 if the session is remote. */
int sd_session_is_remote(const char *session);

/* Return 1 if the session is granted extra device access. */
int sd_session_has_extra_device_access(const char *session);

/* Get state from session. Possible states: online, active, closing.
 * This function is a more generic version of sd_session_is_active(). */
int sd_session_get_state(const char *session, char **ret_state);

/* Determine user ID of session */
int sd_session_get_uid(const char *session, uid_t *ret_uid);

/* Determine username of session */
int sd_session_get_username(const char *session, char **ret_username);

/* Determine seat of session */
int sd_session_get_seat(const char *session, char **ret_seat);

/* Determine the start time of session */
int sd_session_get_start_time(const char *session, uint64_t *ret_usec);

/* Determine the (PAM) service name this session was registered by. */
int sd_session_get_service(const char *session, char **ret_service);

/* Determine the type of this session, i.e. one of "tty", "x11", "wayland", "mir", "web", or "unspecified". */
int sd_session_get_type(const char *session, char **ret_type);

/* Determine the class of this session, i.e. one of "user", "greeter" or "lock-screen". */
int sd_session_get_class(const char *session, char **ret_clazz);

/* Determine the desktop brand of this session, i.e. something like "GNOME", "KDE" or "systemd-console". */
int sd_session_get_desktop(const char *session, char **ret_desktop);

/* Determine the X11 display of this session. */
int sd_session_get_display(const char *session, char **ret_display);

/* Determine the leader process of this session. */
int sd_session_get_leader(const char *session, pid_t *ret_leader);

/* Determine the remote host of this session. */
int sd_session_get_remote_host(const char *session, char **ret_remote_host);

/* Determine the remote user of this session (if provided by PAM). */
int sd_session_get_remote_user(const char *session, char **ret_remote_user);

/* Determine the TTY of this session. */
int sd_session_get_tty(const char *session, char **ret_tty);

/* Determine the VT number of this session. */
int sd_session_get_vt(const char *session, unsigned *ret_vtnr);

/* Return active session and user of seat */
int sd_seat_get_active(const char *seat, char **ret_session, uid_t *ret_uid);

/* Return sessions and users on seat. Returns number of sessions.
 * If sessions is NULL, this returns only the number of sessions. */
int sd_seat_get_sessions(
                const char *seat,
                char ***ret_sessions,
                uid_t **ret_uids,
                unsigned *ret_n_uids);

/* Return whether the seat is multi-session capable */
int sd_seat_can_multi_session(const char *seat) _sd_deprecated_;

/* Return whether the seat is TTY capable, i.e. suitable for showing console UIs */
int sd_seat_can_tty(const char *seat);

/* Return whether the seat is graphics capable, i.e. suitable for showing graphical UIs */
int sd_seat_can_graphical(const char *seat);

/* Return the class of machine */
int sd_machine_get_class(const char *machine, char **ret_clazz);

/* Return the list if host-side network interface indices of a machine */
int sd_machine_get_ifindices(const char *machine, int **ret_ifindices);

/* Get all seats, store in *seats. Returns the number of seats. If
 * seats is NULL, this only returns the number of seats. */
int sd_get_seats(char ***ret_seats);

/* Get all sessions, store in *sessions. Returns the number of
 * sessions. If sessions is NULL, this only returns the number of sessions. */
int sd_get_sessions(char ***ret_sessions);

/* Get all logged in users, store in *users. Returns the number of
 * users. If users is NULL, this only returns the number of users. */
int sd_get_uids(uid_t **ret_users);

/* Get all running virtual machines/containers */
int sd_get_machine_names(char ***ret_machines);

/* Monitor object */
typedef struct sd_login_monitor sd_login_monitor;

/* Create a new monitor. Category must be NULL, "seat", "session",
 * "uid", or "machine" to get monitor events for the specific category
 * (or all). */
int sd_login_monitor_new(const char *category, sd_login_monitor **ret);

/* Destroys the passed monitor. Returns NULL. */
sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m);

/* Flushes the monitor */
int sd_login_monitor_flush(sd_login_monitor *m);

/* Get FD from monitor */
int sd_login_monitor_get_fd(sd_login_monitor *m);

/* Get poll() mask to monitor */
int sd_login_monitor_get_events(sd_login_monitor *m);

/* Get timeout for poll(), as usec value relative to CLOCK_MONOTONIC's epoch */
int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *ret_timeout_usec);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_login_monitor, sd_login_monitor_unref);

_SD_END_DECLARATIONS;

#endif
