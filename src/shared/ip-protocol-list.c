/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <netinet/in.h>

#include "alloc-util.h"
#include "ip-protocol-list.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"

static const struct ip_protocol_name* lookup_ip_protocol(register const char *str, register GPERF_LEN_TYPE len);

#include "ip-protocol-from-name.h"
#include "ip-protocol-to-name.h"

const char *ip_protocol_to_name(int id) {

        if (id < 0)
                return NULL;

        if ((size_t) id >= ELEMENTSOF(ip_protocol_names))
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

int parse_ip_protocol(const char *s) {
        _cleanup_free_ char *str = NULL;
        int i, r;

        assert(s);

        if (isempty(s))
                return IPPROTO_IP;

        /* Do not use strdupa() here, as the input string may come from *
         * command line or config files. */
        str = strdup(s);
        if (!str)
                return -ENOMEM;

        i = ip_protocol_from_name(ascii_strlower(str));
        if (i >= 0)
                return i;

        r = safe_atoi(str, &i);
        if (r < 0)
                return r;

        if (!ip_protocol_to_name(i))
                return -EINVAL;

        return i;
}

const char *ip_protocol_to_tcp_udp(int id) {
        return IN_SET(id, IPPROTO_TCP, IPPROTO_UDP) ?
                ip_protocol_to_name(id) : NULL;
}

int ip_protocol_from_tcp_udp(const char *ip_protocol) {
        int id = ip_protocol_from_name(ip_protocol);
        return IN_SET(id, IPPROTO_TCP, IPPROTO_UDP) ? id : -EINVAL;
}
