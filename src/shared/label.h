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

#include <sys/types.h>
#include <stdbool.h>
#include <sys/socket.h>

int label_init(const char *prefix);
void label_finish(void);

int label_fix(const char *path, bool ignore_enoent, bool ignore_erofs);

int label_socket_set(const char *label);
void label_socket_clear(void);

int label_context_set(const char *path, mode_t mode);
void label_context_clear(void);

void label_free(const char *label);

int label_get_create_label_from_exe(const char *exe, char **label);

int label_mkdir(const char *path, mode_t mode);

int label_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);

int label_apply(const char *path, const char *label);

int label_write_one_line_file_atomic(const char *fn, const char *line);
int label_write_env_file(const char *fname, char **l);
int label_fopen_temporary(const char *path, FILE **_f, char **_temp_path);
