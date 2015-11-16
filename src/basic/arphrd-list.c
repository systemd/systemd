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

#include <net/if_arp.h>
#include <string.h>

#include "arphrd-list.h"
#include "util.h"

static const struct arphrd_name* lookup_arphrd(register const char *str, register unsigned int len);

#include "arphrd-from-name.h"
#include "arphrd-to-name.h"

const char *arphrd_to_name(int id) {

        if (id <= 0)
                return NULL;

        if (id >= (int) ELEMENTSOF(arphrd_names))
                return NULL;

        return arphrd_names[id];
}

int arphrd_from_name(const char *name) {
        const struct arphrd_name *sc;

        assert(name);

        sc = lookup_arphrd(name, strlen(name));
        if (!sc)
                return 0;

        return sc->id;
}

int arphrd_max(void) {
        return ELEMENTSOF(arphrd_names);
}
