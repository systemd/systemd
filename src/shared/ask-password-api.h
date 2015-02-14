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


int ask_password_tty(const char *message, usec_t until, bool echo, const char *flag_file, char **_passphrase);

int ask_password_agent(const char *message, const char *icon, const char *id,
                       usec_t until, bool echo, bool accept_cached, char ***_passphrases);

int ask_password_auto(const char *message, const char *icon, const char *id,
                      usec_t until, bool accept_cached, char ***_passphrases);
