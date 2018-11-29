/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#include "ip-protocol-list.h"
#include "macro.h"

static const struct ip_protocol_name* lookup_ip_protocol(register const char *str, register GPERF_LEN_TYPE len);

#include "ip-protocol-from-name.h"
#include "ip-protocol-to-name.h"

const char *ip_protocol_to_name(int id) {

        if (id < 0)
                return NULL;

        if (id >= (int) ELEMENTSOF(ip_protocol_names))
                return NULL;

        return ip_protocol_names[id];
}

int ip_protocol_from_name(const char *name) {
        const struct ip_protocol_name *sc;

        assert(name);

        sc = lookup_ip_protocol(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}
