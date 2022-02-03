/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "af-list.h"
#include "macro.h"

static const struct af_name* lookup_af(register const char *str, register GPERF_LEN_TYPE len);

#include "af-from-name.h"
#include "af-to-name.h"

const char *af_to_name(int id) {

        if (id <= 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(af_names))
                return NULL;

        return af_names[id];
}

int af_from_name(const char *name) {
        const struct af_name *sc;

        assert(name);

        sc = lookup_af(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}

int af_max(void) {
        return ELEMENTSOF(af_names);
}

const char *af_to_ipv4_ipv6(int id) {
        /* Pretty often we want to map the address family to the typically used protocol name for IPv4 +
         * IPv6. Let's add special helpers for that. */
        return id == AF_INET ? "ipv4" :
                id == AF_INET6 ? "ipv6" : NULL;
}

int af_from_ipv4_ipv6(const char *af) {
        return streq_ptr(af, "ipv4") ? AF_INET :
                streq_ptr(af, "ipv6") ? AF_INET6 : AF_UNSPEC;
}
