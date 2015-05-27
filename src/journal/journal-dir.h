/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Endocode AG

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
#include <dirent.h>

typedef struct JournalDirectory {
        char *path;
        int fd;
        int n_ref;
} JournalDirectory;

int journal_directory_open(const char *path, JournalDirectory **dir);
int journal_directory_new(const char *path, int fd, JournalDirectory **dir);
JournalDirectory *journal_directory_ref(JournalDirectory *dir);
JournalDirectory *journal_directory_unref(JournalDirectory *dir);
int journal_directory_opendir(JournalDirectory *dir, DIR **de);
