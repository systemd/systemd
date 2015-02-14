/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2010 Harald Hoyer

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

#include "util.h"
#include "selinux-util.h"
#include "fileio-label.h"

int write_string_file_atomic_label(const char *fn, const char *line) {
        int r;

        r = mac_selinux_create_file_prepare(fn, S_IFREG);
        if (r < 0)
                return r;

        r = write_string_file_atomic(fn, line);

        mac_selinux_create_file_clear();

        return r;
}

int write_env_file_label(const char *fname, char **l) {
        int r;

        r = mac_selinux_create_file_prepare(fname, S_IFREG);
        if (r < 0)
                return r;

        r = write_env_file(fname, l);

        mac_selinux_create_file_clear();

        return r;
}

int fopen_temporary_label(const char *target,
                          const char *path, FILE **f, char **temp_path) {
        int r;

        r = mac_selinux_create_file_prepare(target, S_IFREG);
        if (r < 0)
                return r;

        r = fopen_temporary(path, f, temp_path);

        mac_selinux_create_file_clear();

        return r;
}
