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

const char* ip_protocol_to_name(int id) {

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

int parse_ip_protocol_full(const char *s, bool relaxed) {
        int r, p;

        assert(s);

        if (isempty(s))
                return IPPROTO_IP;

        /* People commonly use lowercase protocol names, which we can look up very quickly, so let's try that
         * first. */
        r = ip_protocol_from_name(s);
        if (r >= 0)
                return r;

        /* Do not use strdupa() here, as the input string may come from command line or config files. */
        _cleanup_free_ char *t = strdup(s);
        if (!t)
                return -ENOMEM;

        r = ip_protocol_from_name(ascii_strlower(t));
        if (r >= 0)
                return r;

        r = safe_atoi(t, &p);
        if (r < 0)
                return r;
        if (p < 0)
                return -ERANGE;

        /* If @relaxed, we don't check that we have a name for the protocol. */
        if (!relaxed && !ip_protocol_to_name(p))
                return -EPROTONOSUPPORT;

        return p;
}

const char* ip_protocol_to_tcp_udp(int id) {
        return IN_SET(id, IPPROTO_TCP, IPPROTO_UDP) ?
                ip_protocol_to_name(id) : NULL;
}

int ip_protocol_from_tcp_udp(const char *ip_protocol) {
        int id = ip_protocol_from_name(ip_protocol);
        return IN_SET(id, IPPROTO_TCP, IPPROTO_UDP) ? id : -EINVAL;
}
