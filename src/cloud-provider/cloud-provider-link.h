/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "in-addr-util.h"

typedef struct Link Link;
typedef struct NormalizedLinkInfo NormalizedLinkInfo;

typedef struct Manager Manager;

struct Link {
        Manager *manager;

        struct ether_addr mac_address;

        int ifindex;
        char *ifname;

        char *state_file;
};

int link_new(Manager *m, Link **ret, int ifindex, const char *ifname);
Link *link_free(Link *l);
int link_update_rtnl(Link *l, sd_netlink_message *m);
int link_save(Link *l);

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);
