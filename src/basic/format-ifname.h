/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/if.h>

typedef enum {
        FORMAT_IFNAME_IFINDEX              = 1 << 0,
        FORMAT_IFNAME_IFINDEX_WITH_PERCENT = (1 << 1) | FORMAT_IFNAME_IFINDEX,
} FormatIfnameFlag;

int format_ifname_full(int ifindex, FormatIfnameFlag flag, char buf[static IF_NAMESIZE]);
int format_ifname_full_alloc(int ifindex, FormatIfnameFlag flag, char **ret);

static inline int format_ifname(int ifindex, char buf[static IF_NAMESIZE]) {
        return format_ifname_full(ifindex, 0, buf);
}
static inline int format_ifname_alloc(int ifindex, char **ret) {
        return format_ifname_full_alloc(ifindex, 0, ret);
}

static inline char* _format_ifname_full(int ifindex, FormatIfnameFlag flag, char buf[static IF_NAMESIZE]) {
        (void) format_ifname_full(ifindex, flag, buf);
        return buf;
}

#define FORMAT_IFNAME_FULL(index, flag) _format_ifname_full(index, flag, (char[IF_NAMESIZE]){})
#define FORMAT_IFNAME(index) _format_ifname_full(index, 0, (char[IF_NAMESIZE]){})
