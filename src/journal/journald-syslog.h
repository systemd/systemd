/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "journald.h"

void syslog_read_identifier(const char **buf, char **identifier, char **pid);
int syslog_fixup_facility(int priority);

void server_forward_syslog(Server *s, int priority, const char *identifier, const char *message, struct ucred *ucred, struct timeval *tv);

void server_process_syslog_message(Server *s, const char *buf, struct ucred *ucred, struct timeval *tv, const char *label, size_t label_len);
int server_open_syslog_socket(Server *s);
