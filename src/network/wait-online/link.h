/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-netlink.h"

typedef struct Link Link;
typedef struct Manager Manager;

struct Link {
        Manager *manager;

        int ifindex;
        char *ifname;
        unsigned flags;

        bool required_for_online;
        char *operational_state;
        char *state;
};

int link_new(Manager *m, Link **ret, int ifindex, const char *ifname);
Link *link_free(Link *l);
int link_update_rtnl(Link *l, sd_netlink_message *m);
int link_update_monitor(Link *l);

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);
