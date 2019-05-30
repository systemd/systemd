/* SPDX-License-Identifier: LGPL-2.1+ */

#include "format-util.h"
#include "memory-util.h"

char *format_ifname(int ifindex, char buf[static IF_NAMESIZE + 1]) {
        /* Buffer is always cleared */
        memzero(buf, IF_NAMESIZE + 1);
        return if_indextoname(ifindex, buf);
}
