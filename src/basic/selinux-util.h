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

#include <sys/socket.h>
#include <stdbool.h>

#include "macro.h"

bool mac_selinux_use(void);
void mac_selinux_retest(void);

int mac_selinux_init(const char *prefix);
void mac_selinux_finish(void);

int mac_selinux_fix(const char *path, bool ignore_enoent, bool ignore_erofs);
int mac_selinux_apply(const char *path, const char *label);

int mac_selinux_get_create_label_from_exe(const char *exe, char **label);
int mac_selinux_get_our_label(char **label);
int mac_selinux_get_child_mls_label(int socket_fd, const char *exe, const char *exec_label, char **label);
char* mac_selinux_free(char *label);

int mac_selinux_create_file_prepare(const char *path, mode_t mode);
void mac_selinux_create_file_clear(void);

int mac_selinux_create_socket_prepare(const char *label);
void mac_selinux_create_socket_clear(void);

int mac_selinux_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);

DEFINE_TRIVIAL_CLEANUP_FUNC(char*, mac_selinux_free);
