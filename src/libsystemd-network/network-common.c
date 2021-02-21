/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "network-common.h"
#include "string-util.h"

const char *get_ifname(int ifindex, char **ifname) {
        char buf[IF_NAMESIZE + 1];

        assert(ifname);

        /* This sets ifname only when it is not set yet. */

        if (*ifname)
                return *ifname;

        if (ifindex <= 0)
                return NULL;

        if (!format_ifname(ifindex, buf))
                return NULL;

        return *ifname = strdup(buf);
}
