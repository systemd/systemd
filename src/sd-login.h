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

/* Get session from PID */
int sd_pid_get_session(pid_t pid, char **session);

/* Get state from uid. Possible states: offline, lingering, online, active */
int sd_uid_get_state(uid_t uid, char**state);

/* Return 1 if uid has session on seat */
int sd_uid_is_on_seat(uid_t uid, const char *seat);

/* Return 1 if uid has active session on seat */
int sd_uid_is_active_on_seat(uid_t uid, const char *seat);

/* Return 1 if the session is a active */
int sd_session_is_active(const char *session);

/* Determine user id of session */
int sd_session_get_uid(const char *session, uid_t *uid);

/* Determine seat of session */
int sd_session_get_seat(const char *session, char **seat);

/* Return active session and user of seat */
int sd_seat_get_active(const char *seat, char **session, uid_t *uid);

#endif
