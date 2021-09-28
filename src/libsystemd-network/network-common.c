/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "network-common.h"

const char *get_ifname(int ifindex, char **ifname) {
        assert(ifname);

        /* This sets ifname only when it is not set yet. */

        if (*ifname)
                return *ifname;

        if (format_ifname_alloc(ifindex, ifname) < 0)
                return NULL;

        return *ifname;
}
