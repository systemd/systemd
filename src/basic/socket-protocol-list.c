/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include <netinet/in.h>
#include <string.h>

#include "socket-protocol-list.h"
#include "macro.h"

static const struct socket_protocol_name* lookup_socket_protocol(register const char *str, register GPERF_LEN_TYPE len);

#include "socket-protocol-from-name.h"
#include "socket-protocol-to-name.h"

const char *socket_protocol_to_name(int id) {

        if (id < 0)
                return NULL;

        if (id >= (int) ELEMENTSOF(socket_protocol_names))
                return NULL;

        return socket_protocol_names[id];
}

int socket_protocol_from_name(const char *name) {
        const struct socket_protocol_name *sc;

        assert(name);

        sc = lookup_socket_protocol(name, strlen(name));
        if (!sc)
                return 0;

        return sc->id;
}

int socket_protocol_max(void) {
        return ELEMENTSOF(socket_protocol_names);
}
