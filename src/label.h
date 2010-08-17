/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foolabelhfoo
#define foolabelhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

int label_init(void);
void label_finish(void);

int label_fix(const char *path);

int label_socket_set(const char *label);
void label_socket_clear(void);

int label_fifofile_set(const char *label, const char *path);
void label_file_clear(void);

void label_free(const char *label);

int label_get_socket_label_from_exe(const char *exe, char **label);

int label_mkdir(const char *path, mode_t mode);

#endif
