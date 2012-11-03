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

#include "journald-server.h"

/* Make sure not to make this smaller than the maximum coredump
 * size. See COREDUMP_MAX in coredump.c */
#define ENTRY_SIZE_MAX (1024*1024*768)
#define DATA_SIZE_MAX (1024*1024*768)

bool valid_user_field(const char *p, size_t l, bool allow_protected);

void server_process_native_message(Server *s, const void *buffer, size_t buffer_size, struct ucred *ucred, struct timeval *tv, const char *label, size_t label_len);

void server_process_native_file(Server *s, int fd, struct ucred *ucred, struct timeval *tv, const char *label, size_t label_len);

int server_open_native_socket(Server*s);
