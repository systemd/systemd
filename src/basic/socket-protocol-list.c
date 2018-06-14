/* SPDX-License-Identifier: LGPL-2.1+ */

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
