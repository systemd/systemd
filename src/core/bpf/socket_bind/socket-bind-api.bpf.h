/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>

enum socket_bind_action {
        SOCKET_BIND_DENY = 0,
        SOCKET_BIND_ALLOW = 1,
};

/*
 * Ports are in host order.
 */
struct socket_bind_rule {
        __u32 address_family;
        __u16 nr_ports;
        __u16 port_min;

        enum socket_bind_action action;
};

const __u32 socket_bind_max_rules = 128;
