/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <sys/syscall.h>
#include <string.h>

#include "util.h"

#include "syscall-list.h"

static const struct syscall_name* lookup_syscall(register const char *str,
                                                 register unsigned int len);

#include "syscall-to-name.h"
#include "syscall-from-name.h"

const char *syscall_to_name(int id) {
        id = SYSCALL_TO_INDEX(id);
        if (id < 0 || id >= (int) ELEMENTSOF(syscall_names))
                return NULL;

        return syscall_names[id];
}

int syscall_from_name(const char *name) {
        const struct syscall_name *sc;

        assert(name);

        sc = lookup_syscall(name, strlen(name));
        if (!sc)
                return -1;

        return sc->id;
}

int syscall_max(void) {
        return ELEMENTSOF(syscall_names);
}
