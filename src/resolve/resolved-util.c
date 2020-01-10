/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "macro.h"
#include "resolved-util.h"
#include "socket-netlink.h"

int in_addr_ifindex_name_from_string_auto(const char *s, int *family, union in_addr_union *ret, int *ifindex, char **server_name) {
        _cleanup_free_ char *buf = NULL, *name = NULL;
        const char *m;
        int r;

        assert(s);

        m = strchr(s, '#');
        if (m) {
                name = strdup(m+1);
                if (!name)
                        return -ENOMEM;

                buf = strndup(s, m - s);
                if (!buf)
                        return -ENOMEM;

                s = buf;
        }

        r = in_addr_ifindex_from_string_auto(s, family, ret, ifindex);
        if (r < 0)
                return r;

        if (server_name)
                *server_name = TAKE_PTR(name);

        return r;
}
