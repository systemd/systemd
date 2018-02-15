/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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

#include <stdbool.h>

#include "time-util.h"

typedef enum AskPasswordFlags {
        ASK_PASSWORD_ACCEPT_CACHED = 1U << 0,
        ASK_PASSWORD_PUSH_CACHE    = 1U << 1,
        ASK_PASSWORD_ECHO          = 1U << 2, /* show the password literally while reading, instead of "*" */
        ASK_PASSWORD_SILENT        = 1U << 3, /* do no show any password at all while reading */
        ASK_PASSWORD_NO_TTY        = 1U << 4,
        ASK_PASSWORD_NO_AGENT      = 1U << 5,
        ASK_PASSWORD_CONSOLE_COLOR = 1U << 6, /* Use color if /dev/console points to a console that supports color */
} AskPasswordFlags;

int ask_password_tty(int tty_fd, const char *message, const char *keyname, usec_t until, AskPasswordFlags flags, const char *flag_file, char **ret);
int ask_password_agent(const char *message, const char *icon, const char *id, const char *keyname, usec_t until, AskPasswordFlags flag, char ***ret);
int ask_password_keyring(const char *keyname, AskPasswordFlags flags, char ***ret);
int ask_password_auto(const char *message, const char *icon, const char *id, const char *keyname, usec_t until, AskPasswordFlags flag, char ***ret);
