/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "network-common.h"
#include "string-util.h"

int set_ifname(int ifindex, char **ifname) {
        char buf[IF_NAMESIZE + 1];

        assert(ifname);

        /* This sets ifname only when ifname is not set yet.*/

        if (*ifname)
                return 0;

        if (ifindex <= 0)
                return -EINVAL;

        if (!format_ifname(ifindex, buf))
                return -ENODEV;

        *ifname = strdup(buf);
        if (!*ifname)
                return -ENOMEM;

        return 0;
}
