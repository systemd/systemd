/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct TunTap TunTap;

#include "netdev.h"

struct TunTap {
        NetDev meta;

        char *user_name;
        char *group_name;
        bool multi_queue;
        bool packet_info;
        bool vnet_hdr;
        bool keep_fd;
};

DEFINE_NETDEV_CAST(TUN, TunTap);
DEFINE_NETDEV_CAST(TAP, TunTap);
extern const NetDevVTable tun_vtable;
extern const NetDevVTable tap_vtable;

int manager_add_tuntap_fd(Manager *m, int fd, const char *name);
void manager_clear_unmanaged_tuntap_fds(Manager *m);
