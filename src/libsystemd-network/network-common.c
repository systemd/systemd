/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "network-common.h"
#include "string-util.h"

int get_ifname(int ifindex, char **ifname) {
        char buf[IF_NAMESIZE + 1], *copy;
        int r;

        assert(ifname);

        /* This sets ifname only when it is not set yet. */

        if (*ifname)
                return 0;

        r = format_ifname_with_negative_errno(ifindex, buf);
        if (r < 0)
                return r;

        copy = strdup(buf);
        if (!copy)
                return -ENOMEM;

        *ifname = copy;
        return 1;
}
