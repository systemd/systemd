/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
        ASK_PASSWORD_ACCEPT_CACHED = 1,
        ASK_PASSWORD_PUSH_CACHE = 2,
        ASK_PASSWORD_ECHO = 4,                /* show the password literally while reading, instead of "*" */
        ASK_PASSWORD_SILENT = 8,              /* do no show any password at all while reading */
        ASK_PASSWORD_NO_TTY = 16,
        ASK_PASSWORD_NO_AGENT = 32,
} AskPasswordFlags;

int ask_password_tty(const char *message, const char *keyname, usec_t until, AskPasswordFlags flags, const char *flag_file, char **ret);
int ask_password_agent(const char *message, const char *icon, const char *id, const char *keyname, usec_t until, AskPasswordFlags flag, char ***ret);
int ask_password_keyring(const char *keyname, AskPasswordFlags flags, char ***ret);
int ask_password_auto(const char *message, const char *icon, const char *id, const char *keyname, usec_t until, AskPasswordFlags flag, char ***ret);
