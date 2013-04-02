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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fileio-label.h"
#include "label.h"

int write_string_file_atomic_label(const char *fn, const char *line) {
        int r;

        r = label_context_set(fn, S_IFREG);
        if (r  < 0)
                return r;

        write_string_file_atomic(fn, line);

        label_context_clear();

        return r;
}

int write_env_file_label(const char *fname, char **l) {
        int r;

        r = label_context_set(fname, S_IFREG);
        if (r  < 0)
                return r;

        write_env_file(fname, l);

        label_context_clear();

        return r;
}
