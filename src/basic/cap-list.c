/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <string.h>

#include "cap-list.h"
#include "missing.h"
#include "parse-util.h"
#include "util.h"

static const struct capability_name* lookup_capability(register const char *str, register unsigned int len);

#include "cap-from-name.h"
#include "cap-to-name.h"

const char *capability_to_name(int id) {

        if (id < 0)
                return NULL;

        if (id >= (int) ELEMENTSOF(capability_names))
                return NULL;

        return capability_names[id];
}

int capability_from_name(const char *name) {
        const struct capability_name *sc;
        int r, i;

        assert(name);

        /* Try to parse numeric capability */
        r = safe_atoi(name, &i);
        if (r >= 0 && i >= 0)
                return i;

        /* Try to parse string capability */
        sc = lookup_capability(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}

int capability_list_length(void) {
        return (int) ELEMENTSOF(capability_names);
}
